# Ghidra import

`reccmp` supports importing your decompilation progress into [Ghidra](https://github.com/NationalSecurityAgency/ghidra). As of this writing, Ghidra >= 12.0 is supported. There are two different ways of setting this up. They are not mutually exclusive, so you can pick whatever works for your current workflow:

1. Headless import:
    - Starts the import from the command line, which launches Ghidra in headless mode against a local project or a remote repository
      - If run on a local project, other Ghidra instances must be closed first
    - Easier to set up
    - More configurable
2. GUI import:
    - Runs as a Ghidra script in GUI mode
    - May be more convenient because the local Ghidra project does not need to be closed for the import

## Headless setup

This assumes that you have already installed `reccmp`, e.g. in a virtual environment.

- Install Ghidra 12.0 or newer.
- It may be necessary to configure the environment variable `GHIDRA_INSTALL_DIR` to point to your Ghidra installation. See also the [pyghidra documentation](https://pypi.org/project/pyghidra/).
- If there is no Ghidra project for this file yet:
  - Create a Ghidra project (either local or shared), import your original binary you want to decompile, analyse, and save. If this is a shared project, check in the file.
- Close any locally running Ghidra instances.
- Run one of the following commands in the directory where your `reccmp-build.yml` is located:
  - Local project: `reccmp-ghidra-import --target <reccmp-target> --local-project-name <ghidra-project-name> --file <file-inside-ghidra-project>`
    - If necessary, also provide `--local-project-dir`, especially if your Ghidra project is not located in Ghidra's default project directory.
  - Shared project: `RECCMP_GHIDRA_USER=user RECCMP_GHIDRA_PASSWORD=password reccmp-ghidra-import --target <reccmp-target> --remote-url ghidra://<host>[:<port>]/<project-name> --file <file-inside-ghidra-project>`
    - You can optionally provide `--remote-checkin-comment` if you want to customize the check-in comment.
    - If you know what you are doing security wise, you can also provide the username and password via the URL: `--remote-url ghidra://user:password@<host>[:<port>]/<project-name`.

## GUI setup

There are two ways to install the importer:

- Case 1: You only want to use the importer in a decompilation project.
  - Create a virtual environment inside your _decompilation project_ and install `reccmp` there. Make sure to _not_ install `reccmp` in editable mode (don't use `pip install -e`).
  - Your decompilation project needs to have a valid `reccmp-build.yml` next to its `reccmp-project.yml`. This is a known limitation.
- Case 2: You want to actively develop this importer.
  - Create a virtual env in _this repository_ in a top level directory called `.venv` and install this project in editable mode ( `pip install -e .`).
  - Copy [dev_config.example.json](./dev_config.example.json) to `dev_config.json` and configure a decompilation target.

### pyghidra

Since these scripts and its dependencies are written in Python 3, Ghidra must be launched [with pyghidra support enabled](https://github.com/NationalSecurityAgency/ghidra/blob/56d5167e93eb27e01a6c6dfa3d1cb8e7d759df57/README.md?plain=1#L38).

### Script Directory

This step differs slightly depending on your setup.

- Install Ghidra 12.0 or newer.
- In Ghidra, open your project and file, then click _Open Window -> Script Manager_.
- Click the _Manage Script Directories_ button on the top right.
- Click the _Add_ (Plus icon) button.
- You may have to select _File Chooser Options -> Show '.' Files_.
  - Case 1: Select `Lib/site-packages/reccmp/ghidra/scripts` inside your _project's_ virtual environment.
  - Case 2: Select `<this repository's root>/reccmp/ghidra/scripts` (don't select anything within _this_ repository's venv).
- Close the window and click the _Refresh_ button.
- This script should now be available under the folder _reccmp_.

### File matching

Since it is not possible to configure any script parameters in Ghidra, the correct decompilation target needs to be inferred. Currently, this is done via the hash of the original binary, which needs to match the hash configured in `reccmp-project.yml` under `targets/<target>/hash/sha256`.

## Development

- Ghidra keeps the local `reccmp` modules loaded between script runs. Therefore, there is a risk that code changes are not applied until Ghidra is restarted. While a workaround has been implemented (see [the Ghidra imprt script](./scripts/import_functions_and_types_from_pdb.py)), we are not certain that it is perfectly reliable.
- There is a [docker compose setup](./development/compose.yaml) to run a local Ghidra server for developing / testing the remote import functionality.
