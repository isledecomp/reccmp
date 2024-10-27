# Ghidra Scripts

The scripts in this directory provide additional functionality in Ghidra, e.g. imports of symbols and types from the PDB debug symbol file.

## Setup

There are two ways to install this script:
- Case 1: You only want to use this script in a decompilation project.
    - Create a virtual environment inside your _decompilation project_ and install `reccmp` there. Make sure to _not_ install `reccmp` in editable mode (`pip install -e`).
    - Your decompilation project needs to have a valid `reccmp-build.yml` next to its `reccmp-project.yml`. This is a known limitation.
- Case 2: You want to actively develop this script.
    - Create a virtual env in _this repository_ in a top level directory called `.venv` and install this project there (`pip install .` or `pip install -e .`).
    - Copy `dev_config.example.json` to `dev_config.json` and configure a decompilation target.

### Ghidrathon
Since these scripts and its dependencies are written in Python 3, [Ghidrathon](https://github.com/mandiant/Ghidrathon) must be installed first. Follow the instructions and install a recent build (these scripts were tested with Python 3.12 and Ghidrathon v4.0.0).

### Script Directory
This step differs slightly depending on your setup.

- In Ghidra, _Open Window -> Script Manager_.
- Click the _Manage Script Directories_ button on the top right.
- Click the _Add_ (Plus icon) button.
    - Case 1: Select `Lib/site-packages/reccmp/ghidra_scripts` inside your _project's_ virtual environment.
    - Case 2: Select `<this repository's root>/reccmp/ghidra_scripts`. (Don't select anything within this repository's venv, especially if you have installed this project in editable mode).
- Close the window and click the _Refresh_ button.
- This script should now be available under the folder _LEGO1_.


## Development
- Type hints for Ghidra (optional): Download a recent release from https://github.com/VDOO-Connected-Trust/ghidra-pyi-generator,
  unpack it somewhere, and `pip install` that directory in this virtual environment. This provides types and headers for Python.
  Be aware that some of these files contain errors - in particular, `from typing import overload` seems to be missing everywhere, leading to spurious type errors.
- Note that the imported modules persist across multiple runs of the script (see [here](https://github.com/mandiant/Ghidrathon/issues/103)).
  If you indend to modify an imported library, you have to use `import importlib; importlib.reload(${library})` or restart Ghidra for your changes to have any effect. Unfortunately, even that is not perfectly reliable, so you may still have to restart Ghidra for some changes in `isledecomp` to be applied.
