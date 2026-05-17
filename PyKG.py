import os
import queue
import sys
import struct
import threading
import hashlib
import customtkinter as ctk
from tkinter import PhotoImage, filedialog
from pathlib import Path
from collections import defaultdict

HAS_CRYPTO = False
AES = None
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter
    HAS_CRYPTO = True
except ImportError:
    pass

PKG_MAGIC    = b'\x7fPKG'
PKG_TYPE_PS3 = 0x0001
PS3_NPDRM_KEY = bytes.fromhex('2e7b71d7c9c9a14ea3221f188828b8f8')
FLAG_DIR         = 0x04
ITEM_RECORD_SIZE = 0x20
HDR_FMT  = '>4sHHIIIIQQQ48s16s16s'
HDR_SIZE = struct.calcsize(HDR_FMT)
ITEM_FMT = '>IIQQII'
MONO_FONT = 'Courier New' if sys.platform in ('win32', 'darwin') else 'Courier'

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
    }

def make_aes_ctr(iv: bytes, stream_byte_offset: int):
    block_index = stream_byte_offset // 16
    iv_int = int.from_bytes(iv, 'big')
    ctr_val = (iv_int + block_index) & ((1 << 128) - 1)
    ctr = Counter.new(128, initial_value=ctr_val)

    return AES.new(PS3_NPDRM_KEY, AES.MODE_CTR, counter=ctr)

def decrypt_region(f, iv, data_offset, stream_pos, size):
    if size == 0:
        return b''

    block_start = stream_pos & ~0xF
    prefix_len  = stream_pos - block_start
    cipher = make_aes_ctr(iv, block_start)

    f.seek(data_offset + block_start)

    enc = f.read(prefix_len + size)
    plain = cipher.decrypt(enc)

    return plain[prefix_len : prefix_len + size]

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

def find_title_id_and_version(f, items, iv, data_offset, log):
    for (name_off, name_size, item_data_off, item_data_size, flags) in items:
        if name_size == 0 or item_data_size == 0:
            continue

        raw_name = decrypt_region(f, iv, data_offset, name_off, name_size)
        name = raw_name.rstrip(b'\x00').decode('utf-8', errors='replace')

        if name.upper().endswith('PARAM.SFO'):
            sfo_data = decrypt_region(f, iv, data_offset, item_data_off, item_data_size)
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
    h = hashlib.sha1()
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
        f.seek(0)
        hdr = read_header(f)
        item_count = hdr['item_count']
        data_offset = hdr['data_offset']
        iv = hdr['iv']
        content_id = hdr['content_id']

        log(f"CONTENT-ID: {content_id}\n")
        log(f"ITEMS: {item_count}\n")

        table_raw = decrypt_region(f, iv, data_offset, 0, item_count * ITEM_RECORD_SIZE)

        items = []
        for i in range(item_count):
            rec = table_raw[i * ITEM_RECORD_SIZE : (i + 1) * ITEM_RECORD_SIZE]
            name_off, name_size, item_data_off, item_data_size, flags, _ = struct.unpack(ITEM_FMT, rec)
            items.append((name_off, name_size, item_data_off, item_data_size, flags))

        title_id, app_ver, title = find_title_id_and_version(f, items, iv, data_offset, log)
        title_id = str(title_id)
        CHUNK = 512 * 1024

        for index, (name_off, name_size, item_data_off, item_data_size, flags) in enumerate(items):
            if name_size == 0:
                if progress_cb:
                    progress_cb(index + 1, item_count)
                continue

            raw_name = decrypt_region(f, iv, data_offset, name_off, name_size)
            name = raw_name.rstrip(b'\x00').decode('utf-8', errors='replace')
            is_dir = bool(flags & FLAG_DIR)

            if not name or name in ('.', '..'):
                continue

            name = name.replace('\\', '/').strip('/')
            if '\x00' in name:
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
                        data = decrypt_region(f, iv, data_offset, item_data_off + written, chunk_size)
                        if not data:
                            raise IOError("Unexpected EOF while decrypting")

                        out.write(data)
                        written += len(data)
                size_kb = item_data_size / 1024
                log(f"EXTRACTING FILE:  {name}  ({size_kb:,.1f} KB)\n")

            if progress_cb:
                progress_cb(index + 1, item_count)

    return title_id

def find_pkg_files(root: Path) -> list[Path]:
    pkgs = []
    for dirpath, _dirs, files in os.walk(root):
        for fname in files:
            p = Path(dirpath) / fname
            if p.suffix.lower() != '.pkg':
                continue
            pkgs.append(p)
    return sorted(pkgs)

def peek_content_id(pkg_path: Path) -> str:
    try:
        with open(pkg_path, 'rb') as f:
            return read_header(f)['content_id']
    except Exception as exc:
        return f"(error: {exc})"

def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

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
        of.grid_columnconfigure(5, weight=1)

        ctk.CTkButton(of, text="Scan", width=110, command=self.scan).grid(row=0, column=2, padx=(128, 8))

        self.extract_btn = ctk.CTkButton(of, text="Extract All", width=130, fg_color='#1a6b3c', hover_color='#145530',
            command=self.start_extract, state='disabled')
        self.extract_btn.grid(row=0, column=3, padx=(0, 8))

        self.cancel_btn = ctk.CTkButton(of, text="Cancel", width=100, fg_color='#6b1a1a', hover_color='#551414',
            command=self.cancel, state='disabled')
        self.cancel_btn.grid(row=0, column=4)

        self.status_lbl = ctk.CTkLabel(of, text="", text_color='#888', font=ctk.CTkFont(size=12))
        self.status_lbl.grid(row=0, column=5, padx=12, sticky='w')

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

        self.log_box = ctk.CTkTextbox(mp, font=ctk.CTkFont(family=MONO_FONT, size=11),
            activate_scrollbars=True, state='disabled')
        self.log_box.grid(row=1, column=1, sticky='nsew', padx=(8, 0))

        self.progress = ctk.CTkProgressBar(self)
        self.progress.set(0)
        self.progress.grid(row=4, column=0, sticky='ew', padx=16, pady=(0, 14))

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
            cid = peek_content_id(pkg)
            hash_label, meta_label = self.add_list_item(pkg, cid)
            hash_labels.append(hash_label)
            meta_labels.append(meta_label)

        t = threading.Thread(target=self.scan_worker, args=(pkgs, hash_labels, meta_labels), daemon=True)
        t.start()

    def scan_worker(self, pkgs: list[Path], hash_labels: list, meta_labels: list):
        total = len(pkgs)
        for i, (pkg, hash_label) in enumerate(zip(pkgs, hash_labels), 1):
            ok, msg = verify_pkg_hash(pkg)
            self._pkg_hash_ok[pkg] = ok
            color = 'green' if ok else 'red'
            self.after(0, lambda lbl=hash_label, m=msg, c=color: lbl.configure(text=m, text_color=c))
            self.after(0, self.progress.set, i / total)

            try:
                with open(pkg, 'rb') as f:
                    hdr = read_header(f)
                    table_raw = decrypt_region(f, hdr['iv'], hdr['data_offset'], 0, hdr['item_count'] * ITEM_RECORD_SIZE)
                    items = []
                    for j in range(hdr['item_count']):
                        rec = table_raw[j * ITEM_RECORD_SIZE:(j + 1) * ITEM_RECORD_SIZE]
                        name_off, name_size, item_data_off, item_data_size, flags, _ = struct.unpack(ITEM_FMT, rec)
                        items.append((name_off, name_size, item_data_off, item_data_size, flags))
                    tid, version, title = find_title_id_and_version(f, items, hdr['iv'], hdr['data_offset'], lambda x: None)
                lbl = meta_labels[i - 1]
                text = f"{title} \n{tid} | {version}"
                self.after(0, lambda l=lbl, t=text: l.configure(text=t))
            except Exception:
                pass

        self._meta_labels: dict[Path, ctk.CTkLabel] = dict(zip(pkgs, meta_labels))

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
        total = len(pkgs)
        ok = 0
        fail = 0

        self.enqueue_log("\nScanning PKGs for version info...\n")

        pkg_meta = []
        ordered_pkgs = []
        skipped_title_ids: set[str] = set()

        for i, pkg in enumerate(pkgs, 1):
            if self.cancel_flag.is_set():
                self.enqueue_log("Cancelled during scan.\n")
                return

            self.enqueue_log(f"  [{i}/{total}] scanning {pkg.name}\n")

            try:
                with open(pkg, 'rb') as f:
                    hdr = read_header(f)
                    item_count = hdr['item_count']
                    iv = hdr['iv']
                    data_offset = hdr['data_offset']

                    table_raw = decrypt_region(f, iv, data_offset, 0, item_count * ITEM_RECORD_SIZE)

                    items = []
                    for item in range(item_count):
                        rec = table_raw[item * ITEM_RECORD_SIZE:(item + 1) * ITEM_RECORD_SIZE]
                        name_off, name_size, item_data_off, item_data_size, flags, _ = struct.unpack(ITEM_FMT, rec)
                        items.append((name_off, name_size, item_data_off, item_data_size, flags))

                    tid, version, title = find_title_id_and_version(f, items, iv, data_offset, lambda x: None)
                    pkg_meta.append((pkg, title, tid, version, parse_version(version)))

            except Exception as e:
                self.enqueue_log(f"scan failed: {pkg.name}: {e}\n")
                pkg_meta.append((pkg, 'UNKNOWN', 'UNKNOWN', (0, 0)))

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

        for count, pkg in enumerate(ordered_pkgs, 1):
            if self.cancel_flag.is_set():
                self.enqueue_log(f"\nCancelled after {count-1}/{len(ordered_pkgs)} PKGs.\n")
                break

            if not self._pkg_hash_ok.get(pkg, False):
                self.enqueue_log(f"\n[{count}/{len(ordered_pkgs)}] SKIPPED (hash mismatch): {pkg.name}\n")
                for p, title, tid, version, _ in pkg_meta:
                    if p == pkg:
                        skipped_title_ids.add(tid)
                        break
                self.after(0, self.progress.set, count / len(ordered_pkgs))
                continue

            pkg_to_tid: dict[Path, str] = {p: tid for p, title, tid, version, _ in pkg_meta}
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

    def add_list_item(self, p: Path, cid: str):
        fr = ctk.CTkFrame(self.list_frame, fg_color=('gray83', 'gray22'), corner_radius=4)
        fr.pack(fill='x', pady=2, padx=2)
        meta_label = ctk.CTkLabel(fr, text="", font=ctk.CTkFont(size=11),
                    anchor='w', justify='left')
        meta_label.pack(fill='x', padx=8, pady=(4,0))
        ctk.CTkLabel(fr, text=p.name, font=ctk.CTkFont(size=10),
                    anchor='w').pack(fill='x', padx=8, pady=(4, 0))
        hash_label = ctk.CTkLabel(fr, text="Verifying Hash...",
                    font=ctk.CTkFont(size=10), text_color="#ced900",
                    anchor='w', justify='left')
        hash_label.pack(fill='x', padx=8)
        ctk.CTkLabel(fr, text=str(p.parent),
                    font=ctk.CTkFont(size=10), text_color='#666',
                    anchor='w', wraplength=270, justify='left').pack(fill='x', padx=8, pady=(0, 4))

        
        return hash_label, meta_label

    def set_status(self, msg: str):
        self.after(0, self.status_lbl.configure, {'text': msg})

if __name__ == '__main__':
    App().mainloop()
