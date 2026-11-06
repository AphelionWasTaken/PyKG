# PyKG
PyKG is a program which can extract or build PlayStation 3 PKG files.

You can use this tool to explore PKG contents, or you can use it to bulk install PKGs to RPCS3 if they are in multiple folders.

You can also use it to rebuild PKGs or create your own PKGs.

Features:
- Windows, Linux, and MacOS support
- Retail and debug/homebrew PKG support
- A clean and easy to use GUI
- PARAM.SFO verification of PKG info
- Recursive folder scanning
- Hash verification of PKG files
- Custom PARAM.SFO creation for homebrew PKGs
<p align="center">
  <img width="576" height="457" alt="image" src="https://github.com/user-attachments/assets/eb92ae51-b2d9-4eb6-bd6e-4a0cff8f2a7f" />
</p>

Installation
============
Just download the appropriate PyKG.zip from [Releases](https://github.com/AphelionWasTaken/PyKG/releases/latest) for your operating system, extract the folder, and run the executable.

Using PyKG
============
Extracting PKGs
------------
Once the program is open, select the folder containing your PKGs. PyKG scans folders recursively, so you can point it to a folder containing subfolders which contain PKGs and it will scan all of them.

Next, select where you'd like to extract the files to. If you're extracting title updates to RPCS3, you'll need to point it to dev_hdd0/game in your RPCS3 installation.

Hit the Scan button and PyKG will list all of the PKG files it finds.

Hit the Extract and PyKG will begin extracting the PKGs to your selected destination folder.

Creating PKGs
------------
Once the program is open, click the "Repackage" button to open the PKG creation dialogue window.

Select the folder containing the files you would like to make into a PKG.

Next, either select an existing pkg to copy the header data, flags, and PARAM.SFO from as a template, or select "custom PKG"

If you selected "Custom PKG", you must input the content ID and select a PKG type.

If you are making a PKG type that requires a PARAM.SFO and you do not have one and you are not using an existing PKG as a template, you must check the "Create PARAM.SFO" and fill out the PARAM.SFO fields. If you do not fill out a field, default values will be used.

Select the output folder for the PKG file and hit "Repackage" to being creating the PKG.

Building PyKG
============
PyKG does not need to be "built". Releases are created via PyInstaller. If you would rather run this directly from the source code, this program requires [Python 3](https://www.python.org/downloads/). It is included with most Linux Distros, although you may need to upgrade to a more recent version.

You will also need the CustomTkinter and Pycryptodomex modules installed to run this program. To install these, open any terminal and type `pip install customtkinter` and `pip install pycryptodomex`, respectively.

If you have already cloned/downloaded this repo, you can easily install both of these modules by navigating to your PyKG directory (where requirements.txt exists), and type `pip install -r requirements.txt`.

Once you have the modules, clone this repo or just click on the green Code button and download the zip folder.

Extract the files and <ins>move the icons from the Icons folder into the root of your PyKG folder</ins> (next to PyKG.py), then run PyKG.py with Python. Or run it in a terminal by navigating to the directory containing PyKG.py and typing `python PyKG.py`.

Or run it however else you want, I don't care, I'm not a cop.
