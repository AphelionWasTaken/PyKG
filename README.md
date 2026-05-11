# PyKG
PyKG is a program which extracts PlayStation 3 PKG files.

You can use this tool to explore PKG contents, or you can use it to bulk install PKGs to RPCS3 if they are in multiple folders.

Features:
- Windows, Linux, and MacOS support
- A clean and easy to use GUI
- PARAM.SFO verification of PKG info

Installation
============
Just download the appropriate PyKG.zip from [Releases](https://github.com/AphelionWasTaken/PyKG/releases/latest) for your operating system, extract the folder, and run the executable.

Using PyKG
============
Once the program is open, select the folder containing your PKGs. PyKG scans folders recursively, so you can point it to a folder containing subfolders which contain PKGs and it will scan all of them.

Next, select where you'd like to extract the files to. If you're extracting title updates to RPCS3, you'll need to point it to dev_hdd0/game in your RPCS3 installation.

Hit the Scan button and PyKG will list all of the PKG files it finds.

Hit the Extract and PyKG will begin extracting the PKGs to your selected destination folder.

Building PyKG
============
PyKG does not need to be "built". Releases are created via PyInstaller. If you would rather run this directly from the source code, this program requires [Python 3](https://www.python.org/downloads/). It is included with most Linux Distros, although you may need to upgrade to a more recent version.

You will also need the CustomTkinter and Pycryptodomex modules installed to run this program. To install these, open any terminal and type `pip install customtkinter` and `pip install pycryptodomex`, respectively.

If you have already cloned/downloaded this repo, you can easily install both of these modules by navigating to your PyKG directory (where requirements.txt exists), and type `pip install -r requirements.txt`.

Once you have the modules, clone this repo or just click on the green Code button and download the zip folder.

Extract the files and <ins>move the icons from the Icons folder into the root of your PyKG folder</ins> (next to PyKG.py), then run PyKG.py with Python. Or run it in a terminal by navigating to the directory containing PyKG.py and typing `python PyKG.py`.

Or run it however else you want, I don't care, I'm not a cop.
