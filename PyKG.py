import os
import re
import queue
import sys
import struct
import threading
import hashlib
import customtkinter as ctk
from tkinter import PhotoImage, filedialog
from dataclasses import dataclass
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

HAS_CRYPTO = False
AES = None
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    HAS_CRYPTO = True
except ImportError:
    pass

PKG_MAGIC = b'\x7fPKG'
PKG_TYPE_PS3 = 0x0001
PKG_RELEASE_TYPE_DEBUG = 0x0000
PKG_RELEASE_TYPE_RELEASE = 0x8000
PS3_NPDRM_KEY = bytes.fromhex('2e7b71d7c9c9a14ea3221f188828b8f8')
FLAG_DIR = 0x04
ITEM_RECORD_SIZE = 0x20
HDR_FMT = '>4sHHIIIIQQQ48s16s16s'
HDR_SIZE = struct.calcsize(HDR_FMT)
ITEM_FMT = '>IIQQII'
MONO_FONT = 'Courier New' if sys.platform in ('win32', 'darwin') else 'Courier'
PKG_DIGEST_BLOCK = 0x40
PKG_FOOTER_SIZE = 0x60
TYPE_OVERWRITE = 0x80000000
TYPE_NPDRM_SELF = 0x01
TYPE_RAW = 0x03
CRYPT_CHUNK = 512 * 1024
CONTENT_ID_RE = re.compile(r'^[A-Z0-9]{6}-[A-Z0-9]{9}_[0-9]{2}-[A-Z0-9_]{16}$')

@dataclass
class PkgSettings:
    content_id: str
    content_type: int = 5
    package_flags: int = 0xE
    drm_type: int = 3
    package_revision: int = 0x1061
    package_version: int = 0
    eboot_is_npdrm_self: bool = False

def align16(n: int) -> int:
    return (n + 15) & ~15

def read_header(f) -> dict:
    f.seek(0)
    raw = f.read(HDR_SIZE)
    if len(raw) < HDR_SIZE:
        raise ValueError("File too small to be a PKG")

    (magic, revision, pkg_type, meta_offset, meta_count, header_size, item_count,
     total_size, data_offset, data_size, content_id_raw, digest, riv) = struct.unpack(HDR_FMT, raw)

    if magic != PKG_MAGIC:
        raise ValueError(f"Not a valid PKG file (magic={magic!r})")

    if pkg_type != PKG_TYPE_PS3:
        raise ValueError(f"Not a PS3 PKG (type={pkg_type:#06x}). "
                         "Only PS3 NPDRM PKGs are supported.")

    content_id = content_id_raw.rstrip(b"\x00").decode('ascii', errors='replace')
    return {
        'item_count': item_count,
        'data_offset': data_offset,
        'content_id': content_id,
        'iv': riv,
        'qa_digest': digest,
        'release_type': revision,
    }

def get_debug_keystream_block(qa_digest: bytes, block_index: int) -> bytes:
    qa_0 = qa_digest[0:8]
    qa_1 = qa_digest[8:16]
    buffer = bytearray(64)
    buffer[0:8] = qa_0
    buffer[8:16] = qa_0
    buffer[16:24] = qa_1
    buffer[24:32] = qa_1
    buffer[56:64] = struct.pack(">Q", block_index)

    return hashlib.sha1(buffer).digest()[:16]

def make_aes_ctr(iv: bytes, stream_byte_offset: int):
    block_index = stream_byte_offset // 16
    iv_int = int.from_bytes(iv, 'big')
    ctr_val = (iv_int + block_index) & ((1 << 128) - 1)
    ctr = Counter.new(128, initial_value=ctr_val)

    return AES.new(PS3_NPDRM_KEY, AES.MODE_CTR, counter=ctr)

def decrypt_region(f, hdr: dict, stream_pos: int, size: int) -> bytes:
    if size == 0:
        return b''

    data_offset = hdr['data_offset']
    release_type = hdr['release_type']
    block_start = stream_pos & ~0xF
    prefix_len = stream_pos - block_start
    num_bytes = prefix_len + size
    num_blocks = (num_bytes + 15) // 16

    f.seek(data_offset + block_start)
    enc = f.read(num_blocks * 16)

    if release_type == PKG_RELEASE_TYPE_DEBUG:
        qa_digest = hdr['qa_digest']
        block_index = block_start // 16
        plaintext = bytearray()
        chunks = (enc[offset:offset + 16] for offset in range(0, len(enc), 16))
        for i, chunk in enumerate(chunks):
            keystream = get_debug_keystream_block(qa_digest, block_index + i)
            plaintext.extend(a ^ b for a, b in zip(chunk, keystream))
        return bytes(plaintext)[prefix_len : prefix_len + size]
    else:
        iv = hdr['iv']
        iv_int = int.from_bytes(iv, 'big')
        ctr_val = (iv_int + block_start // 16) & ((1 << 128) - 1)
        ctr = Counter.new(128, initial_value=ctr_val)
        cipher = AES.new(PS3_NPDRM_KEY, AES.MODE_CTR, counter=ctr)
        plaintext = cipher.decrypt(enc)
        return plaintext[prefix_len : prefix_len + size]

def parse_sfo(data: bytes) -> dict | None:
    if data[:4] != b'\0PSF':
        return None

    key_table_start = struct.unpack_from('<I', data, 0x08)[0]
    data_table_start = struct.unpack_from('<I', data, 0x0C)[0]
    entry_count = struct.unpack_from('<I', data, 0x10)[0]

    result = {}

    for i in range(entry_count):
        entry_off = 0x14 + i * 0x10

        key_off, fmt, size, max_size, data_off = struct.unpack_from(
            '<HHIII', data, entry_off
        )

        key_start = key_table_start + key_off
        key_end = data.find(b'\0', key_start)
        if key_end == -1:
            continue

        key = data[key_start:key_end].decode('utf-8', errors='ignore')

        val_start = data_table_start + data_off
        raw = data[val_start:val_start + size]
        value = raw.rstrip(b'\0').decode('utf-8', errors='ignore')

        if key == 'TITLE_ID':
            result['TITLE_ID'] = value
        elif key == 'APP_VER':
            result['APP_VER'] = value
        elif key == 'TITLE':
            result['TITLE'] = value

    return result if 'TITLE_ID' in result else None

def parse_version(v: str) -> tuple:
    parts = v.strip().split('.')
    cleaned = []

    for p in parts:
        try:
            cleaned.append(int(p))
        except ValueError:
            cleaned.append(0)

    while len(cleaned) < 2:
        cleaned.append(0)

    return tuple(cleaned)

def find_title_id_and_version(f, items, hdr, log):
    for (name_off, name_size, item_data_off, item_data_size, flags) in items:
        if name_size == 0 or item_data_size == 0:
            continue

        raw_name = decrypt_region(f, hdr, name_off, name_size)
        name = raw_name.rstrip(b'\x00').decode('utf-8', errors='replace')

        if name.upper().endswith('PARAM.SFO'):
            sfo_data = decrypt_region(f, hdr, item_data_off, item_data_size)
            info = parse_sfo(sfo_data)
            if info:
                tid = info.get('TITLE_ID')
                ver = info.get('APP_VER')
                title = info.get('TITLE', '')

                log(f"TITLE: {title}\n")
                log(f"TITLE_ID: {tid}\n")
                log(f"APP_VER: {ver}\n")

                return tid, ver, title
    log("ERROR: PARAM.SFO DOES NOT CONTAIN ONE OF THE FOLLOWING: TITLE_ID or APP_VER")
    return None, None, None


def verify_pkg_hash(pkg_path: Path, log_cb=None) -> tuple[bool, str]:
    CHUNK = 512 * 1024
    try:
        file_size = pkg_path.stat().st_size
    except OSError as e:
        return False, f"Could not get file attributes: {e}"

    if file_size < 32:
        return False, "File too small to contain a PackageDigest"

    body_size = file_size - 32
    h = hashlib.sha1(usedforsecurity=False)
    try:
        with open(pkg_path, 'rb') as f:
            remaining = body_size
            while remaining > 0:
                chunk = f.read(min(CHUNK, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
            stored_hash = f.read(20)
    except OSError as e:
        return False, f"Could not read file: {e}"

    if stored_hash == bytes(20):
        return True, "No PackageDigest (homebrew PKG)"

    computed_hash = h.digest()
    if computed_hash == stored_hash:
        return True, f"SHA-1 Hash: {computed_hash.hex()}"
    else:
        return False, (f"Hash MISMATCH!\n"
                       f"stored: {stored_hash.hex()}\n"
                       f"computed: {computed_hash.hex()}")

def extract_pkg(pkg_path: Path, dest_root: Path, progress_cb=None, log_cb=None) -> str:
    def log(msg: str):
        if log_cb:
            log_cb(msg)

    with open(pkg_path, 'rb') as f:
        hdr = read_header(f)
        item_count = hdr['item_count']
        content_id = hdr['content_id']

        log(f"CONTENT-ID: {content_id}\n")
        log(f"ITEMS: {item_count}\n")

        table_raw = decrypt_region(f, hdr, 0, item_count * ITEM_RECORD_SIZE)

        items = []
        for i in range(item_count):
            rec = table_raw[i * ITEM_RECORD_SIZE: (i + 1) * ITEM_RECORD_SIZE]
            name_off, name_size, item_data_off, item_data_size, flags, _ = struct.unpack(ITEM_FMT, rec)
            items.append((name_off, name_size, item_data_off, item_data_size, flags))

        title_id, app_ver, title = find_title_id_and_version(f, items, hdr, log)
        title_id = str(title_id)

        raw_names = []
        for (name_off, name_size, _, _, _) in items:
            if name_size > 0:
                raw = decrypt_region(f, hdr, name_off, name_size)
                raw_names.append(raw.rstrip(b'\x00').decode('utf-8', errors='replace'))
            else:
                raw_names.append('')

        path_pkg = is_path_pkg(raw_names)
        if path_pkg:
            log("Detected pypkg path-traversal PKG — using virtual PS3 root extraction.\n")

        CHUNK = 512 * 1024

        for index, ((name_off, name_size, item_data_off, item_data_size, flags), name) in enumerate(zip(items, raw_names)):
            if name_size == 0:
                if progress_cb:
                    progress_cb(index + 1, item_count)
                continue

            is_dir = bool(flags & FLAG_DIR)

            if not name or name in ('.', '..'):
                continue

            if path_pkg:
                dest = resolve_path_pkg_dest(name, dest_root)
                if dest is None:
                    log(f"SKIPPED (unsafe path): {name}\n")
                    continue
            else:
                name = name.replace('\\', '/').strip('/')
                if not name or '\x00' in name:
                    continue
                dest = dest_root / title_id / name

            if is_dir:
                if dest.exists() and dest.is_file():
                    dest.unlink()
                dest.mkdir(parents=True, exist_ok=True)
            else:
                if dest.parent.exists() and dest.parent.is_file():
                    dest.parent.unlink()
                dest.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with open(dest, "wb") as out:
                    while written < item_data_size:
                        chunk_size = min(CHUNK, item_data_size - written)
                        data = decrypt_region(f, hdr, item_data_off + written, chunk_size)
                        if not data:
                            raise IOError("Unexpected EOF while decrypting")
                        out.write(data)
                        written += len(data)
                size_kb = item_data_size / 1024
                log(f"EXTRACTING FILE:  {name}  ({size_kb:,.1f} KB)\n")

            if progress_cb:
                progress_cb(index + 1, item_count)

    return title_id

def crypt_stream(hdr: dict, data: bytes, stream_pos: int) -> bytes:
    if stream_pos % 16 or len(data) % 16:
        raise ValueError("crypt_stream needs 16-byte aligned position and length")
    if not data:
        return b''
    block_index = stream_pos // 16

    if hdr['release_type'] == PKG_RELEASE_TYPE_DEBUG:
        qa = hdr['qa_digest']
        buf = bytearray(64)
        buf[0:8] = buf[8:16] = qa[0:8]
        buf[16:24] = buf[24:32] = qa[8:16]
        keystream = bytearray(len(data))
        sha1, pack_into = hashlib.sha1, struct.pack_into
        for i in range(len(data) // 16):
            pack_into('>Q', buf, 56, block_index + i)
            keystream[i * 16:i * 16 + 16] = sha1(buf).digest()[:16]
        return (int.from_bytes(data, 'big') ^ int.from_bytes(keystream, 'big')).to_bytes(len(data), 'big')

    ctr_val = (int.from_bytes(hdr['iv'], 'big') + block_index) & ((1 << 128) - 1)
    ctr = Counter.new(128, initial_value=ctr_val, allow_wraparound=True)
    return AES.new(PS3_NPDRM_KEY, AES.MODE_CTR, counter=ctr).encrypt(data)

def _debug_keystream(key16: bytes, nbytes: int) -> bytes:
    n = (nbytes + 15) // 16
    return b''.join(get_debug_keystream_block(key16, i) for i in range(n))[:nbytes]

def debug_digest_blocks(header: bytes, meta_packets: bytes) -> tuple[bytes, bytes]:
    hdr_sha = hashlib.sha1(header).digest()[3:19]
    meta_sha = hashlib.sha1(meta_packets).digest()[3:19]
    pad_enc = _debug_keystream(meta_sha, 0x30)
    pad_enc2 = bytes(a ^ b for a, b in zip(pad_enc, _debug_keystream(hdr_sha, 0x30)))
    return hdr_sha + pad_enc2, meta_sha + pad_enc

def read_template(tpl_path: Path) -> dict:
    with open(tpl_path, 'rb') as f:
        hdr = read_header(f)
        f.seek(0)
        raw = f.read(HDR_SIZE)
        (_magic, revision, pkg_type, meta_off, meta_cnt, meta_size, item_count,
         total_size, data_off, data_size, content_id_raw, digest, riv) = struct.unpack(HDR_FMT, raw)

        f.seek(meta_off)
        meta_blob = f.read(data_off - meta_off)

        table = decrypt_region(f, hdr, 0, item_count * ITEM_RECORD_SIZE)
        order, flags_by_name = [], {}
        for i in range(item_count):
            rec = table[i * ITEM_RECORD_SIZE:(i + 1) * ITEM_RECORD_SIZE]
            n_off, n_size, _, _, flags, _ = struct.unpack(ITEM_FMT, rec)
            name = decrypt_region(f, hdr, n_off, n_size).rstrip(b'\0').decode('utf-8', 'replace')
            order.append(name)
            flags_by_name[name] = flags

    return dict(scratch=False, revision=revision, pkg_type=pkg_type, meta_off=meta_off,
                meta_cnt=meta_cnt, meta_size=meta_size, total_size=total_size,
                data_off=data_off, data_size=data_size, content_id_raw=content_id_raw,
                digest=digest, riv=riv, meta_blob=meta_blob, order=order, flags=flags_by_name)

def scratch_template(s: PkgSettings) -> dict:
    if not CONTENT_ID_RE.match(s.content_id):
        raise ValueError("Content ID must look like 'UP0001-BLUS30001_00-MYHOMEBREW000000' "
                         "(6 chars - 9 chars _ 2 digits - 16 chars)")
    flags = {'USRDIR/EBOOT.BIN': TYPE_OVERWRITE | TYPE_NPDRM_SELF} if s.eboot_is_npdrm_self else {}
    return dict(scratch=True, revision=PKG_RELEASE_TYPE_DEBUG, pkg_type=PKG_TYPE_PS3,
                meta_off=0xC0, meta_cnt=5, meta_size=0x80, total_size=0, data_off=0x140,
                data_size=0, content_id_raw=s.content_id.encode('ascii').ljust(0x30, b'\0'),
                digest=bytes(16), riv=bytes(16), meta_blob=None, order=[], flags=flags,
                settings=s)

def scratch_metadata_packets(s: PkgSettings, data_size: int) -> bytes:
    p = (struct.pack('>III', 1, 4, s.drm_type) +
         struct.pack('>III', 2, 4, s.content_type) +
         struct.pack('>III', 3, 4, s.package_flags) +
         struct.pack('>IIQ', 4, 8, data_size) +
         struct.pack('>IIHH', 5, 4, s.package_revision, s.package_version))
    assert len(p) == 0x40
    return p

def patch_metadata(blob: bytearray, tpl: dict, new_total: int, new_data: int, log) -> None:
    pos = 0
    for _ in range(tpl['meta_cnt']):
        if pos + 8 > len(blob):
            break
        pid, psz = struct.unpack_from('>II', blob, pos)
        if pid == 0x04 and psz == 8:
            old = struct.unpack_from('>Q', blob, pos + 8)[0]
            if old == tpl['total_size']:
                struct.pack_into('>Q', blob, pos + 8, new_total)
            elif old == tpl['data_size']:
                struct.pack_into('>Q', blob, pos + 8, new_data)
            else:
                log(f"NOTE: metadata size packet ({old:#x}) matches neither total_size nor "
                    f"data_size of the template; left unchanged.\n")
        pos += 8 + psz

def _walk_sorted(root: Path, prefix: str = '') -> list[tuple[str, Path, bool]]:
    entries = sorted(os.scandir(root), key=lambda e: e.name)
    out = [(prefix + entry.name, Path(entry.path), False) for entry in entries if not entry.is_dir()]
    for entry in entries:
        if entry.is_dir():
            out.append((prefix + entry.name, Path(entry.path), True))
            out.extend(_walk_sorted(Path(entry.path), prefix + entry.name + '/'))
    return out

def collect_repack_items(src_dir: Path, tpl_order: list[str]) -> list[tuple[str, Path, bool]]:
    walked = _walk_sorted(src_dir)
    if not tpl_order:
        return walked
    by_name = {name: (name, path, dir) for name, path, dir in walked}
    ordered = [by_name[name] for name in tpl_order if name in by_name]
    seen = {name for name, _, _ in ordered}
    return ordered + [item for item in walked if item[0] not in seen]

def _pack_hdr(revision, pkg_type, tpl, n_items, total, data_size, content_id_raw, digest, riv) -> bytes:
    return struct.pack(HDR_FMT, PKG_MAGIC, revision, pkg_type, tpl['meta_off'], tpl['meta_cnt'],
                       tpl['meta_size'], n_items, total, tpl['data_off'], data_size,
                       content_id_raw, digest, riv)

def repack_pkg(src_dir: Path, template_pkg: Path | None, out_pkg: Path, settings: PkgSettings | None = None,
               progress_cb=None, log_cb=None, cancel_flag=None) -> None:
    def log(msg):
        if log_cb:
            log_cb(msg)

    if template_pkg is not None:
        tpl = read_template(template_pkg)
        if is_path_pkg(tpl['order']):
            raise ValueError("Path-traversal (pypkg) PKGs can't be used as a template.")
    elif settings is not None:
        tpl = scratch_template(settings)
    else:
        raise ValueError("Give either a template PKG or PkgSettings.")
    scratch = tpl['scratch']
    revision = tpl['revision']
    debug = revision == PKG_RELEASE_TYPE_DEBUG

    items = collect_repack_items(src_dir, tpl['order'])
    if not items:
        raise ValueError("Source folder is empty.")
    present = {name for name, _, _ in items}
    for item in tpl['order']:
        if item not in present:
            log(f"NOTE: '{item}' is in the template but not in the folder - dropped.\n")

    names_raw = [n.encode('utf-8') for n, _, _ in items]
    pos = len(items) * ITEM_RECORD_SIZE
    name_offs = []
    for name in names_raw:
        name_offs.append(pos)
        pos += align16(len(name))

    records, sizes = [], []
    for (name, path, is_dir), n_off, nr in zip(items, name_offs, names_raw):
        default = TYPE_OVERWRITE | (FLAG_DIR if is_dir else TYPE_RAW)
        old = tpl['flags'].get(name)
        flags = old if old is not None and ((old & 0xFF) == FLAG_DIR) == is_dir else default
        size = 0 if is_dir else path.stat().st_size
        records.append(struct.pack(ITEM_FMT, n_off, len(nr), pos, size, flags, 0))
        sizes.append(size)
        if not is_dir:
            pos += align16(size)
    data_size = pos
    total_size = tpl['data_off'] + data_size + PKG_FOOTER_SIZE
    table_blob = b''.join(records) + b''.join(nr + bytes(align16(len(nr)) - len(nr)) for nr in names_raw)
    work_total = max(sum(sizes) * (2 if debug else 1), 1)
    work_done = 0

    def tick(n):
        nonlocal work_done
        work_done += n
        if progress_cb:
            progress_cb(work_done, work_total)

    if debug:
        qa = hashlib.sha1()
        for (name, path, is_dir), size in zip(items, sizes):
            if is_dir:
                continue
            with open(path, 'rb') as src:
                while True:
                    if cancel_flag is not None and cancel_flag.is_set():
                        raise InterruptedError("Cancelled")
                    chunk = src.read(CRYPT_CHUNK)
                    if not chunk:
                        break
                    qa.update(chunk)
                    tick(len(chunk))
        qa.update(_pack_hdr(revision, tpl['pkg_type'], tpl, len(items), total_size, data_size,
                            bytes(0x30), bytes(16), bytes(16)))
        qa.update(table_blob)
        qa_digest = qa.digest()[:16]
        riv = get_debug_keystream_block(qa_digest, 0xFFFFFFFFFFFFFFFF) if scratch else tpl['riv']
    else:
        qa_digest, riv = tpl['digest'], tpl['riv']

    new_hdr = _pack_hdr(revision, tpl['pkg_type'], tpl, len(items), total_size, data_size,
                        tpl['content_id_raw'], qa_digest, riv)

    if scratch:
        meta_packets = scratch_metadata_packets(tpl['settings'], data_size)
    else:
        blob = bytearray(tpl['meta_blob'])
        patch_metadata(blob, tpl, total_size, data_size, log)
        if tpl['meta_size'] != len(blob) or len(blob) <= PKG_DIGEST_BLOCK:
            raise ValueError("Unexpected metadata layout in template.")
        meta_packets = bytes(blob[:-PKG_DIGEST_BLOCK])

    rtlDigestBlockHdr = bytes(PKG_DIGEST_BLOCK - 8) + hashlib.sha1(new_hdr).digest()[-8:]
    rtlDigestBlockMeta = bytes(PKG_DIGEST_BLOCK - 8) + hashlib.sha1(meta_packets).digest()[-8:]

    if debug:
        hdr_digest, meta_digest = debug_digest_blocks(new_hdr, meta_packets)
    else:
        hdr_digest, meta_digest = rtlDigestBlockHdr, rtlDigestBlockMeta

    crypto_hdr = dict(release_type=revision, iv=riv, qa_digest=qa_digest)
    tmp = out_pkg.with_name(out_pkg.name + '.tmp')
    sha = hashlib.sha1(usedforsecurity=False)
    stream_pos = 0

    try:
        with open(tmp, 'wb') as out:
            def emit(b: bytes):
                out.write(b)
                sha.update(b)

            def emit_plain(plain: bytes):
                nonlocal stream_pos
                plain += bytes(-len(plain) % 16)
                emit(crypt_stream(crypto_hdr, plain, stream_pos))
                stream_pos += len(plain)

            emit(new_hdr)
            emit(hdr_digest)
            emit(meta_packets)
            emit(meta_digest)
            if out.tell() != tpl['data_off']:
                raise ValueError("Header/metadata size doesn't line up with data_offset.")

            emit_plain(table_blob)

            for (name, path, is_dir), size in zip(items, sizes):
                if is_dir:
                    continue
                if cancel_flag is not None and cancel_flag.is_set():
                    raise InterruptedError("Cancelled")
                log(f"PACKING FILE: {name} ({size / 1024:,.1f} KB)\n")
                written = 0
                with open(path, 'rb') as src:
                    while written < size:
                        chunk = src.read(min(CRYPT_CHUNK, size - written))
                        if not chunk:
                            raise IOError(f"'{name}' shrank while packing")
                        if len(chunk) % 16 and written + len(chunk) < size:
                            raise IOError(f"short read on '{name}'")
                        emit_plain(chunk)
                        written += len(chunk)
                        tick(len(chunk))

            if stream_pos != data_size:
                raise ValueError(f"Internal layout error: wrote {stream_pos:#x}, expected {data_size:#x}")

            if scratch:
                out.write(bytes(PKG_FOOTER_SIZE))
            else:
                emit(bytes(PKG_DIGEST_BLOCK))
                out.write(sha.digest() + bytes(12))

        os.replace(tmp, out_pkg)

    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

def find_pkg_files(root: Path) -> list[Path]:
    pkgs = []
    for dirpath, dirs, files in os.walk(root):
        for fname in files:
            p = Path(dirpath) / fname
            if p.suffix.lower() != '.pkg':
                continue
            pkgs.append(p)
    return sorted(pkgs)

def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

def is_path_pkg(items_names: list[str]) -> bool:
    for name in items_names:
        if name.startswith('../') or name.startswith('..\\'):
            return True
    return False

def resolve_path_pkg_dest(raw_name: str, dest_root: Path) -> Path | None:
    name = raw_name.replace('\\', '/')
    parts = [p for p in name.split('/') if p]
    resolved = []

    for part in parts:
        if part == '..':
            if resolved:
                resolved.pop()
        elif part != '.':
            resolved.append(part)

    if not resolved:
        return None

    result = dest_root.joinpath(*resolved)

    try:
        result.resolve().relative_to(dest_root.resolve())
    except ValueError:
        return None

    return result

class CTkMultiSelectDropdown(ctk.CTkFrame):
    def __init__(self, master, options, placeholder="Select options", **kwargs):
        super().__init__(master, fg_color='transparent', **kwargs)

        self.options = options
        self.selected = set()
        self.placeholder = placeholder
        self.dropdown = None
        self.variables = {}

        self.grid_columnconfigure(0, weight=1)

        self.button = ctk.CTkButton(self, text=placeholder, anchor='w', command=self.toggle_dropdown)
        self.button.grid(row=0, column=0, sticky='ew')

    def toggle_dropdown(self):
        if self.dropdown and self.dropdown.winfo_exists():
            self.close_dropdown()
        else:
            self.open_dropdown()

    def open_dropdown(self):
        self.dropdown = ctk.CTkToplevel(self)
        self.dropdown.withdraw()
        self.dropdown.title("Select options")
        self.dropdown.resizable(False, False)

        self.dropdown.transient(self.winfo_toplevel())

        container = ctk.CTkScrollableFrame(
            self.dropdown,
            width=220,
            height=180
        )
        container.grid(sticky='nsew', padx=5, pady=5)

        self.variables = {}

        for label, value in self.options.items():
            var = ctk.BooleanVar(value=value in self.selected)
            self.variables[value] = var

            checkbox = ctk.CTkCheckBox(
                container,
                text=label,
                variable=var,
                command=lambda v=value: self.update_selection(v)
            )
            checkbox.grid(sticky='w', padx=10, pady=5)

        self.dropdown.update_idletasks()

        x = self.button.winfo_rootx()
        y = self.button.winfo_rooty() + self.button.winfo_height()

        self.dropdown.geometry(f"+{x}+{y}")

        self.dropdown.deiconify()
        self.dropdown.lift()

    def close_dropdown(self):
        if self.dropdown and self.dropdown.winfo_exists():
            self.dropdown.destroy()

        self.dropdown = None

    def update_selection(self, value):
        if self.variables[value].get():
            self.selected.add(value)
        else:
            self.selected.discard(value)

        self.update_label()

    def update_label(self):
        if not self.selected:
            self.button.configure(text=self.placeholder)
            return

        labels = [
            label for label, value in self.options.items()
            if value in self.selected
        ]

        self.button.configure(text=", ".join(labels))

    def get(self):
        return list(self.selected)

    def set(self, values):
        self.selected = set(values)
        self.update_label()

class RepackDialog(ctk.CTkToplevel):
    TYPES = {
        "Game / Homebrew App (GameExec)": (5, 0xE),
        "Game Data / DLC (GameData)": (4, 0x8),
    }

    CATEGORIES = {
        "Hard Drive Game": "HG",
        "Disc Game": "DG",
        "Game Data": "GD",
        "Application": "AP",
        "Homebrew": "HB",
        "Video Content": "AV"
    }

    RESOLUTION_OPTIONS = {
        "480p (4:3)": 0x001,
        "576p (4:3)": 0x002,
        "720p (16:9)": 0x004,
        "1080p (16:9)": 0x008,
        "480p (16:9)": 0x010,
        "576p (16:9)": 0x020,
    }

    SOUND_OPTIONS = {
        "LPCM 2.0": 0x001,
        "LPCM 5.1": 0x004,
        "LPCM 7.1": 0x010,
        "Dolby Digital 5.1": 0x100,
        "DTS 5.1": 0x200,
    }

    SFO_MAX = {
        "APP_VER": 8,
        "CATEGORY": 4,
        "LICENSE": 0x200,
        "PS3_SYSTEM_VER": 8,
        "TITLE": 0x80,
        "TITLE_ID": 0x10,
        "VERSION": 8,
    }

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Repackage PKG")
        self.geometry('800x360')
        self.grid_columnconfigure((1,2,3,4,5), weight=1)
        self.grab_set()
        self.entries = {}
 
        self.mode_var = ctk.StringVar(value="template")
        self.type_var = ctk.StringVar(value=next(iter(self.TYPES)))
        self.cat_var = ctk.StringVar(value=next(iter(self.CATEGORIES)))
        self.param_var = ctk.BooleanVar()

        def row(r, label, key, cmd=None, ph=""):
            ctk.CTkLabel(self, text=label, anchor='e', width=110).grid(row=r, column=0, padx=(12, 8), pady=6)
            e = ctk.CTkEntry(self, placeholder_text=ph)
            e.grid(row=r, column=1, columnspan=4, sticky='ew', pady=6)
            self.entries[key] = e
            if cmd:
                ctk.CTkButton(self, text="Browse", width=80, command=cmd).grid(row=r, column=5, padx=12)

        self.param_frame = ctk.CTkFrame(self, fg_color='transparent')
        self.param_frame.grid(row=7, column=0, columnspan=6, sticky='ew', padx=12)
        self.param_frame.grid_remove()
        self.param_frame.grid_columnconfigure((1, 3), weight=1, uniform='p')

        fields = [
            ('tid', "Title ID:", "BCUS12345", 1, 0),
            ('appver', "App Version:", "01.00", 2, 0),
            ('ver', "Version:", "01.00", 3, 0),
            ('sysver', "System Version:", "04.80", 4, 0),
            ('boot', "Bootable:", "0", 5, 0),
            ('att', "Attribute:", "0", 4, 2),
            ('lisc', "License:", "0", 5, 2),
            ('par', "Parental Control:", "0", 1, 2),
        ]
        for key, label, ph, r, c in fields:
            ctk.CTkLabel(self.param_frame, text=label, anchor='e', width=110).grid(
                row=r, column=c, padx=(0, 8), pady=6, sticky='e')
            entry = ctk.CTkEntry(self.param_frame, placeholder_text=ph)
            entry.grid(row=r, column=c + 1, padx=(0, 12), pady=6, sticky='ew')
            self.entries[key] = entry

        def toggle_widget():
            if self.param_var.get():
                self.param_frame.grid()
                self.geometry('800x600')
            else:
                self.param_frame.grid_remove()
                self.geometry('800x360')

        row(0, "Folder:", 'src', self.pick_src, "Folder whose contents become the PKG")
        
        ctk.CTkRadioButton(self, text="Use an original PKG as template", variable=self.mode_var,
                           value="template").grid(row=1, column=1, sticky='w', pady=(10, 2))
        
        row(2, "Template PKG:", 'tpl', self.pick_tpl, "Original .pkg (keeps header, metadata, flags)")
        
        ctk.CTkRadioButton(self, text="Custom PKG (no original)", variable=self.mode_var,
                           value="custom").grid(row=3, column=1, sticky='w', pady=(10, 2))
        
        row(4, "Content ID:", 'cid', None, "UP0001-BLUS30001_00-MYHOMEBREW000000")
        
        ctk.CTkCheckBox(self, text="Create Param.SFO?", variable=self.param_var, command=toggle_widget).grid(row=6, column=1, sticky='w', pady=6)
        
        ctk.CTkLabel(self, text="Type:", anchor='e', width=110).grid(row=5, column=0, padx=(12, 8), pady=6)
        ctk.CTkOptionMenu(self, variable=self.type_var, values=list(self.TYPES)).grid(
                          row=5, column=1, sticky='w', pady=6)
        
        row(16, "Output:", 'out', self.pick_out, "Where to save the new .pkg")
        
        ctk.CTkButton(self, text="Repackage", fg_color='#1a6b3c', hover_color='#145530',
                      command=self.go).grid(row=17, column=1, sticky='ew', pady=14, padx=148)
        
        ctk.CTkLabel(self.param_frame, text="Title:", anchor='e', width=110).grid(row=0, column=0, padx=(0, 8), pady=6, sticky='e')
        title_entry = ctk.CTkEntry(self.param_frame, placeholder_text="Title")
        title_entry.grid(row=0, column=1, columnspan=3, padx=(0, 120), pady=6, sticky='ew')
        self.entries["title"] = title_entry
        
        ctk.CTkLabel(self.param_frame, text="Category:", anchor='e', width=110).grid(row=1, column=2, padx=(0, 8), pady=6, sticky='e')
        ctk.CTkOptionMenu(self.param_frame, variable=self.cat_var,
                          values=list(self.CATEGORIES.keys())).grid(row=1, column=3, padx=(0, 12), pady=6, sticky='ew')
        
        ctk.CTkLabel(self.param_frame, text="Resolution:", anchor='e', width=110).grid(row=2, column=2, padx=(0, 8), pady=6, sticky='e')
        resolution_menu = CTkMultiSelectDropdown(
            self.param_frame,
            self.RESOLUTION_OPTIONS,
            placeholder="Select resolutions"
        )
        resolution_menu.grid(row=2, column=3, sticky='ew', padx=(0,10), pady=5)
        self.entries['resolution'] = resolution_menu

        ctk.CTkLabel(self.param_frame, text="Sound Format:", anchor='e', width=110).grid(row=3, column=2, padx=(0, 8), pady=6, sticky='e')
        sound_menu = CTkMultiSelectDropdown(
            self.param_frame,
            self.SOUND_OPTIONS,
            placeholder="Select audio formats"
        )
        sound_menu.grid(row=3, column=3, sticky='ew', padx=(0,10), pady=5)
        self.entries['sound'] = sound_menu

    def get(self, key):
        return self.entries[key].get().strip()

    def set_entry(self, key, value):
        e = self.entries[key]
        e.delete(0, 'end')
        e.insert(0, value)

    def flags(self, key):
        value = 0
        for v in self.entries[key].get():
            value |= v
        return value

    def pick_src(self):
        d = filedialog.askdirectory(title="Folder to Package")
        if not d:
            return
        self.set_entry('src', d)
        sfo = Path(d) / 'PARAM.SFO'
        if sfo.is_file() and not self.get('cid'):
            info = parse_sfo(sfo.read_bytes())
            if info:
                tid = info['TITLE_ID']
                self.set_entry('cid', f"UP0001-{tid}_00-{tid}0000000"[:36])

    def pick_tpl(self):
        p = filedialog.askopenfilename(title="Original PKG", filetypes=[('PS3 PKG', '*.pkg')])
        if p:
            self.entries['tpl'].delete(0, 'end')
            self.entries['tpl'].insert(0, p)
            self.mode_var.set('template')

    def pick_out(self):
        p = filedialog.asksaveasfilename(title="Save PKG As", defaultextension='.pkg', filetypes=[('PS3 PKG', '*.pkg')])
        if p:
            self.entries['out'].delete(0, 'end')
            self.entries['out'].insert(0, p)

    def create_sfo(self, parameters, src_dir):
        key_table = bytearray()
        data_table = bytearray()
        index = []

        for key, value in sorted(parameters.items()):
            key_off = len(key_table)
            key_table += key.encode('ascii') + b'\0'

            if isinstance(value, int):
                fmt, used, max_len = 0x0404, 4, 4
                data = struct.pack('<I', value)
            else:
                max_len = self.SFO_MAX.get(key, 0x40)
                raw = str(value).encode('utf-8')[:max_len - 1]
                used = len(raw) + 1
                fmt = 0x0204
                data = raw + b'\0' * (max_len - len(raw))

            index.append((key_off, fmt, used, max_len, len(data_table)))
            data_table += data

        key_table_off = 20 + 16 * len(index)
        padding = (-(key_table_off + len(key_table))) % 4
        data_table_off = key_table_off + len(key_table) + padding

        header = struct.pack('<4sIIII', b'\0PSF', 0x00000101,
                            key_table_off, data_table_off, len(index))
        index_blob = b"".join(struct.pack('<HHIII', *e) for e in index)

        with open(Path(src_dir) / "PARAM.SFO", 'wb') as f:
            f.write(header + index_blob + key_table + b'\0' * padding + data_table)

    def to_int(self, key):
        try:
            return int(self.get(key) or 0)
        except ValueError:
            return 0

    def go(self):
        log = self.app.enqueue_log
        src, out = self.get('src'), self.get('out')
        if not src or not Path(src).is_dir() or not out:
            log("Pick a source folder and an output file.\n")
            return

        if self.mode_var.get() == 'template':
            tpl = self.get('tpl')
            if not tpl or not Path(tpl).is_file():
                log("Pick a template PKG, or switch to Custom PKG.\n")
                return
            if Path(tpl).resolve() == Path(out).resolve():
                log("Output can't overwrite the template.\n")
                return
            tpl, settings = Path(tpl), None
        else:
            ctype, flags = self.TYPES[self.type_var.get()]
            tpl = None
            settings = PkgSettings(content_id=self.get('cid').upper(),
                                content_type=ctype, package_flags=flags)

        if self.param_var.get():
            self.create_sfo({
                "TITLE": self.get('title') or "My PKG",
                "TITLE_ID": self.get('tid') or "BCUS12345",
                "CATEGORY": self.CATEGORIES[self.cat_var.get()],
                "APP_VER": self.get('appver') or "01.00",
                "VERSION": self.get('ver') or "01.00",
                "PS3_SYSTEM_VER": self.get('sysver') or "04.80",
                "BOOTABLE": self.to_int('boot'),
                "ATTRIBUTE": self.to_int('att'),
                "LICENSE": self.get('lisc') or "Homebrew",
                "PARENTAL_LEVEL": self.to_int('par'),
                "RESOLUTION": self.flags('resolution'),
                "SOUND_FORMAT": self.flags('sound'),
            }, Path(src))

        self.app.start_repack(Path(src), tpl, settings, Path(out))
        self.destroy()

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PyKG - Batch PKG Extractor")
        self.geometry('920x700')
        self.minsize(720, 540)
        self.resizable(True, True)
        if sys.platform == 'win32':
            self.iconbitmap(resource_path("AphIcon.ico"))
        elif sys.platform in ['linux', 'darwin']:
            icon = PhotoImage(file=resource_path("AphIcon.png"))
            self.after(0, lambda: self.iconphoto(True, icon))

        self._pkg_files: list[Path] = []
        self._worker: threading.Thread | None = None
        self.cancel_flag = threading.Event()
        self._log_queue: queue.Queue[str | None] = queue.Queue()

        self.build_ui()
        self.drain_log()

        if not HAS_CRYPTO:
            self.enqueue_log(
                "AES library not found.\n"
                "Run: pip install pycryptodomex\n\n"
            )

    def build_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        self.folder_var = ctk.StringVar()
        self.dest_var = ctk.StringVar()
        

        pf = ctk.CTkFrame(self, fg_color='transparent')
        pf.grid(row=1, column=0, sticky='ew', padx=16, pady=(14, 0))
        pf.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(pf, text="PKG folder:", width=120, anchor='e').grid(row=0, column=0, padx=(0, 8), pady=4)
        ctk.CTkEntry(pf, textvariable=self.folder_var, placeholder_text="Root folder to scan recursively for .pkg files").grid(row=0, column=1, sticky='ew', pady=4)
        ctk.CTkButton(pf, text="Browse", width=80, command=self.browse_src).grid(row=0, column=2, padx=(8, 0), pady=4)

        ctk.CTkLabel(pf, text="Destination:", width=120, anchor='e').grid(row=1, column=0, padx=(0, 8), pady=4)
        ctk.CTkEntry(pf, textvariable=self.dest_var, placeholder_text="<rpcs3 data dir>/dev_hdd0/game").grid(row=1, column=1, sticky='ew', pady=4)
        ctk.CTkButton(pf, text="Browse", width=80, command=self.browse_dst).grid(row=1, column=2, padx=(8, 0), pady=4)

        of = ctk.CTkFrame(self, fg_color='transparent')
        of.grid(row=2, column=0, sticky='ew', padx=16, pady=(10, 0))
        of.grid_columnconfigure(6, weight=1)

        ctk.CTkButton(of, text="Scan", width=110, command=self.scan).grid(row=0, column=2, padx=(128, 8))

        self.extract_btn = ctk.CTkButton(of, text="Extract All", width=130, fg_color='#1a6b3c', hover_color='#145530',
            command=self.start_extract, state='disabled')
        self.extract_btn.grid(row=0, column=3, padx=(0, 8))

        self.cancel_btn = ctk.CTkButton(of, text="Cancel", width=100, fg_color='#6b1a1a', hover_color='#551414',
            command=self.cancel, state='disabled')
        self.cancel_btn.grid(row=0, column=4)
        
        self.repack_btn = ctk.CTkButton(of, text="Repackage…", width=130, command=self.open_repack_dialog)
        self.repack_btn.grid(row=0, column=5, padx=(8, 0))

        self.status_lbl = ctk.CTkLabel(of, text="", text_color='#888', font=ctk.CTkFont(size=12))
        self.status_lbl.grid(row=0, column=6, padx=12, sticky='w')

        mp = ctk.CTkFrame(self, fg_color='transparent')
        mp.grid(row=3, column=0, sticky='nsew', padx=16, pady=12)
        mp.grid_columnconfigure(0, weight=2)
        mp.grid_columnconfigure(1, weight=3)
        mp.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(mp, text="PKG FILES FOUND", font=ctk.CTkFont(size=11, weight='bold'),
                     text_color='#444').grid(row=0, column=0, sticky='w', padx=4)
        ctk.CTkLabel(mp, text="EXTRACTION LOG", font=ctk.CTkFont(size=11, weight='bold'),
                     text_color='#444').grid(row=0, column=1, sticky="w", padx=(16, 4))

        self.list_frame = ctk.CTkScrollableFrame(mp)
        self.list_frame.grid(row=1, column=0, sticky='nsew', padx=(0, 8))
        self.list_frame.grid_columnconfigure(0, weight=1)

        self.log_box = ctk.CTkTextbox(mp, font=ctk.CTkFont(family=MONO_FONT, size=11),
            activate_scrollbars=True, state='disabled')
        self.log_box.grid(row=1, column=1, sticky='nsew', padx=(8, 0))

        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.grid(row=4, column=0, sticky='ew', padx=16, pady=(0, 14))

    def open_repack_dialog(self):
        if not HAS_CRYPTO:
            self.enqueue_log("Install pycryptodomex to enable repackaging.\n")
            return
        RepackDialog(self)

    def start_repack(self, src, tpl, settings, out):
        self.cancel_flag.clear()
        self.repack_btn.configure(state='disabled')
        self.cancel_btn.configure(state='normal')
        self.progress.set(0)
        threading.Thread(target=self.repack_worker, args=(src, tpl, settings, out), daemon=True).start()

    def repack_worker(self, src, tpl, settings, out):
        try:
            self.enqueue_log(f"\nRepackaging {src} -> {out}\n")
            repack_pkg(src, tpl, out, settings=settings,
                    progress_cb=lambda d, t: self.after(0, self.progress.set, d / t),
                    log_cb=self.enqueue_log, cancel_flag=self.cancel_flag)
            ok, msg = verify_pkg_hash(out)
            self.enqueue_log(f"\nDone. Verify: {msg}\n")
            self.set_status("Repack complete." if ok else "Repack finished with a hash problem.")
        except InterruptedError:
            self.enqueue_log("\nRepack cancelled.\n")
        except Exception as exc:
            self.enqueue_log(f"\nREPACK FAILED: {exc}\n")
        finally:
            self.after(0, lambda: (self.repack_btn.configure(state='normal'),
                                self.cancel_btn.configure(state='disabled')))

    def enqueue_log(self, msg: str):
        self._log_queue.put(msg)

    def drain_log(self):
        wrote = False
        try:
            self.log_box.configure(state='normal')
            while True:
                msg = self._log_queue.get_nowait()
                self.log_box.insert('end', msg)
                wrote = True
        except queue.Empty:
            pass
        finally:
            self.log_box.configure(state='disabled')
            if wrote:
                self.log_box.see('end')
        self.after(100, self.drain_log)

    def log_clear(self):
        while not self._log_queue.empty():
            try:
                self._log_queue.get_nowait()
            except queue.Empty:
                break

        self.log_box.configure(state='normal')
        self.log_box.delete('1.0', 'end')
        self.log_box.configure(state='disabled')

    def browse_src(self):
        pkg_folder = filedialog.askdirectory(title="Select PKG Source Folder")
        if pkg_folder:
            self.folder_var.set(pkg_folder)

    def browse_dst(self):
        dest_dir = filedialog.askdirectory(title="Select Output Folder (dev_hdd0/game for RPCS3 Installation)")
        if dest_dir:
            self.dest_var.set(dest_dir)

    def scan(self):
        folder = self.folder_var.get().strip()
        if not folder or not Path(folder).is_dir():
            self.enqueue_log("Please select a valid PKG source folder.\n")
            return

        self.log_clear()
        self.clear_list()
        self._pkg_files = []
        self._pkg_hash_ok = {}
        self._pkg_meta = {} 
        self.extract_btn.configure(state='disabled')
        self.progress.set(0)

        pkgs = find_pkg_files(Path(folder))
        if not pkgs:
            self.enqueue_log("No PKG files found.\n")
            self.set_status("No PKGs found.")
            return

        self._pkg_files = pkgs
        self.enqueue_log(f"Found {len(pkgs)} PKG file(s).\n\n")

        hash_labels = []
        meta_labels = []
        for pkg in pkgs:
            hash_label, meta_label = self.add_list_item(pkg)
            hash_labels.append(hash_label)
            meta_labels.append(meta_label)

        t = threading.Thread(target=self.scan_worker, args=(pkgs, hash_labels, meta_labels), daemon=True)
        t.start()

    def scan_worker(self, pkgs: list[Path], hash_labels: list, meta_labels: list):
        total = len(pkgs)

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(verify_pkg_hash, pkg): (i, pkg, hash_label)
                    for i, (pkg, hash_label) in enumerate(zip(pkgs, hash_labels), 1)}

            for future in as_completed(futures):
                i, pkg, hash_label = futures[future]
                ok, msg = future.result()
                self._pkg_hash_ok[pkg] = ok
                color = 'green' if ok else 'red'
                self.after(0, lambda lbl=hash_label, m=msg, c=color: lbl.configure(text=m, text_color=c))
                self.after(0, self.progress.set, i / total)
        
        for i, (pkg, meta_label) in enumerate(zip(pkgs, meta_labels), 1):
            try:
                with open(pkg, 'rb') as f:
                    hdr = read_header(f)
                    table_raw = decrypt_region(f, hdr, 0, hdr['item_count'] * ITEM_RECORD_SIZE)
                    items = []
                    for j in range(hdr['item_count']):
                        rec = table_raw[j * ITEM_RECORD_SIZE:(j + 1) * ITEM_RECORD_SIZE]
                        name_off, name_size, item_data_off, item_data_size, flags, _ = struct.unpack(ITEM_FMT, rec)
                        items.append((name_off, name_size, item_data_off, item_data_size, flags))
                    tid, version, title = find_title_id_and_version(f, items, hdr, lambda x: None)
                    self._pkg_meta[pkg] = (title or 'UNKNOWN', tid or 'UNKNOWN', version or '0.00', parse_version(version or '0.00'))
                text = f"{title or 'UNKNOWN'}\n{tid or 'UNKNOWN'} | {version or '0.00'}"
                self.after(0, lambda l=meta_label, t=text: l.configure(text=t))
            except Exception:
                self._pkg_meta[pkg] = ('UNKNOWN', 'UNKNOWN', '0.00', (0, 0))

        self.set_status(f"{total} PKG(s) ready.")
        self.after(0, self.progress.set, 0)
        if HAS_CRYPTO:
           self.after(0, lambda: self.extract_btn.configure(state='normal'))
        else:
            self.enqueue_log("Install pycryptodomex to enable extraction.\n")


    def start_extract(self):
        dest = self.dest_var.get().strip()
        if not dest:
            self.enqueue_log("Please set the output folder (dev_hdd0/game for RPCS3 installation).\n")
            return
        if not self._pkg_files:
            self.enqueue_log("No PKGs queued - run a scan first.\n")
            return

        dest_path = Path(dest)
        dest_path.mkdir(parents=True, exist_ok=True)

        self.cancel_flag.clear()
        self.extract_btn.configure(state='disabled')
        self.cancel_btn.configure(state='normal')
        self.progress.set(0)

        self._worker = threading.Thread(target=self.worker_fn, args=(list(self._pkg_files), dest_path), daemon=True)
        self._worker.start()

    def cancel(self):
        self.cancel_flag.set()
        self.enqueue_log("\nCancelling after current file…\n")

    def worker_fn(self, pkgs: list[Path], dest: Path):
        ok = 0
        fail = 0
        pkg_meta = []
        ordered_pkgs = []
        skipped_title_ids: set[str] = set()

        self.enqueue_log("\nScanning PKGs for version info...\n")

        for pkg in pkgs:
            if pkg in self._pkg_meta:
                title, tid, version, ver = self._pkg_meta[pkg]
            else:
                title, tid, version, ver = 'UNKNOWN', 'UNKNOWN', '0.00', (0, 0)
            pkg_meta.append((pkg, title, tid, version, ver))

        groups = defaultdict(list)

        for pkg, title, tid, version, ver in pkg_meta:
            groups[tid].append((pkg, version, ver))

        for tid in groups:
            groups[tid].sort(key=lambda x: x[2])

        for tid in sorted(groups.keys()):
            for pkg, version, _ in groups[tid]:
                ordered_pkgs.append(pkg)

                self.enqueue_log(f"Queued: {tid} | Version: {version} | File: {pkg.name}\n")

        self.enqueue_log("\nExtraction order finalized.\n")

        pkg_to_tid: dict[Path, str] = {p: tid for p, title, tid, version, _ in pkg_meta}
        for count, pkg in enumerate(ordered_pkgs, 1):
            if self.cancel_flag.is_set():
                self.enqueue_log(f"\nCancelled after {count-1}/{len(ordered_pkgs)} PKGs.\n")
                break

            if not self._pkg_hash_ok.get(pkg, False):
                self.enqueue_log(f"\n[{count}/{len(ordered_pkgs)}] SKIPPED (hash mismatch): {pkg.name}\n")
                skipped_title_ids.add(pkg_to_tid[pkg])
                self.after(0, self.progress.set, count / len(ordered_pkgs))
                continue

            pkg_tid = pkg_to_tid.get(pkg)
            if pkg_tid in skipped_title_ids:
                self.enqueue_log(f"\n[{count}/{len(ordered_pkgs)}] SKIPPED (title ID {pkg_tid} has failed PKG): {pkg.name}\n")
                self.after(0, self.progress.set, count / len(ordered_pkgs))
                continue

            self.set_status(f"Extracting {count}/{len(ordered_pkgs)}…")

            self.enqueue_log(f"\n[{count}/{len(ordered_pkgs)}] {pkg.name}\n"
                f"{pkg.parent}\n")

            def prog(done, total, counter=count):
                frac = (counter - 1 + done / max(total, 1)) / len(ordered_pkgs)
                self.after(0, self.progress.set, frac)

            try:
                title_id = extract_pkg(pkg, dest, progress_cb=prog, log_cb=self.enqueue_log)
                self.enqueue_log(f"\nFinished: {dest / title_id}\n")
                ok = ok + 1

            except Exception as exc:
                import traceback
                self.enqueue_log(f"\nFAILED: {exc}\n")
                self.enqueue_log(traceback.format_exc() + "\n")
                fail = fail + 1

        self.after(0, self.progress.set, 1.0)

        summary = f"Done — {ok} extracted, {fail} failed."
        self.enqueue_log(f"\n{'─' * 56}\n{summary}\n")

        self.set_status(summary)
        self.after(0, self.extract_btn.configure, {'state': 'normal'})
        self.after(0, self.cancel_btn.configure, {'state': 'disabled'})

    def clear_list(self):
        for w in self.list_frame.winfo_children():
            w.destroy()

    def add_list_item(self, p: Path):
        fr = ctk.CTkFrame(self.list_frame, fg_color=('gray83', 'gray22'), corner_radius=4)
        fr.grid(sticky='ew', pady=2, padx=2)
        meta_label = ctk.CTkLabel(fr, text="Scanning PKG Data...", font=ctk.CTkFont(size=11),
                    anchor='w', justify='left')
        meta_label.grid(sticky='ew', padx=8, pady=(4,0))
        ctk.CTkLabel(fr, text=p.name, font=ctk.CTkFont(size=10),
                    anchor='w').grid(sticky='ew', padx=8, pady=(4, 0))
        hash_label = ctk.CTkLabel(fr, text="Verifying Hash...",
                    font=ctk.CTkFont(size=10), text_color="#ced900",
                    anchor='w', justify='left')
        hash_label.grid(sticky='ew', padx=8)
        ctk.CTkLabel(fr, text=str(p.parent),
                    font=ctk.CTkFont(size=10), text_color='#666',
                    anchor='w', wraplength=270, justify='left').grid(sticky='ew', padx=8, pady=(0, 4))

        
        return hash_label, meta_label

    def set_status(self, msg: str):
        self.after(0, self.status_lbl.configure, {'text': msg})

if __name__ == '__main__':
    App().mainloop()
