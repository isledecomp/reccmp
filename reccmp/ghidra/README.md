# Ghidra import

`reccmp` supports importing your decompilation progress into [Ghidra](https://github.com/NationalSecurityAgency/ghidra). There are two different ways of setting this up. They are not mutually exclusive, so you can pick whatever works for your current workflow:

1. Via [pyghidra](https://pypi.org/project/pyghidra/):
    - Runs in headless mode against a local project or a remote repository
      - If run on a local project, other Ghidra instances must be closed first
    - Easier to set up
    - More configurable
    - Requires Ghidra 11.3 or newer
2. Via a [Ghidrathon](https://github.com/mandiant/Ghidrathon) script:
    - Runs as a Ghidra plugin in GUI mode
    - May be more convenient because the local Ghidra project does not need to be closed for the import

## Setup for pyghidra

This assumes that you have already installed `reccmp`, e.g. in a virtual environment.

- Install Ghidra 11.3 or newer.
- It may be necessary to configure the environment variable `GHIDRA_INSTALL_DIR` to point to your Ghidra installation. See also the [pyghidra documentation](https://pypi.org/project/pyghidra/).
- If there is no Ghidra project for this file yet:
  - Create a Ghidra project (either local or shared), import your original binary you want to decompile, analyse, and save. If this is a shared project, check in the file.
- Close any locally running Ghidra instances.
- Run one of the following commands in the directory where your `reccmp-build.yml` is located:
  - Local project: `reccmp-ghidra-import --target <reccmp-target> --local-project-name <ghidra-project-name> --file <file-inside-ghidra-project>`
    - If necessary, also provide `--local-project-dir`, especially if your Ghidra project is not located in the default directory.
  - Shared project: `reccmp-ghidra-import --target <reccmp-target> --remote-url ghidra://<user>:<password>@<host>[:port]/<project-name> --file <file-inside-ghidra-project>`
    - You can optionally provide `--remote-checkin-comment` if you want to customize the checkin comment.

## Setup for Ghidrathon

There are two ways to install this script:

- Case 1: You only want to use this script in a decompilation project.
  - Create a virtual environment inside your _decompilation project_ and install `reccmp` there. Make sure to _not_ install `reccmp` in editable mode (`pip install -e`).
  - Your decompilation project needs to have a valid `reccmp-build.yml` next to its `reccmp-project.yml`. This is a known limitation.
- Case 2: You want to actively develop this script.
  - Create a virtual env in _this repository_ in a top level directory called `.venv` and install this project in editable mode ( `pip install -e .`).
  - Copy [dev_config.example.json](./dev_config.example.json) to `dev_config.json` and configure a decompilation target.

### Ghidrathon

Since these scripts and its dependencies are written in Python 3, [Ghidrathon](https://github.com/mandiant/Ghidrathon) must be installed first. Follow the instructions and install a recent build (these scripts were tested with Python 3.12 and Ghidrathon v4.0.0).

### Script Directory

This step differs slightly depending on your setup.

- In Ghidra, _Open Window -> Script Manager_.
- Click the _Manage Script Directories_ button on the top right.
- Click the _Add_ (Plus icon) button.
- You may have to select _File Chooser Options -> Show '.' Files_.
  - Case 1: Select `Lib/site-packages/reccmp/ghidra/scripts` inside your _project's_ virtual environment.
  - Case 2: Select `<this repository's root>/reccmp/ghidra/scripts` (don't select anything within this repository's venv).
- Close the window and click the _Refresh_ button.
- This script should now be available under the folder _reccmp_.

### File names

Since it is not possible to configure any script parameters in Ghidra, the correct decompilation target needs to be inferred. Currently, this is done via the file name of the original binary when you first imported the file into Ghidra. This needs to match the file name configured in `reccmp-project.yml` under `targets/<target>/filename`.

## Development

- Note that when running the scripts via Ghidrathon, imported modules persist across multiple runs of the script (see also[this issue](https://github.com/mandiant/Ghidrathon/issues/103)).
    If you indend to modify an imported library, you have to use `import importlib; importlib.reload(${library})` or restart Ghidra for your changes to have any effect. Unfortunately, even that is not perfectly reliable, so you may still have to restart Ghidra for some `reccmp` code changes to be applied.
- There is a [docker compose setup](./development/compose.yaml) to run a local Ghidra server for developing / testing the remote import functionality.
