# Ghidra import

`reccmp` supports importing your decompilation progress into
[Ghidra](https://github.com/NationalSecurityAgency/ghidra) via
[pyghidra](https://pypi.org/project/pyghidra/).

- Runs in headless mode against a local project or a remote repository
  - If run on a local project, other Ghidra instances must be closed first
- Requires Ghidra 12.0.2 or newer

## Setup

This assumes that you have already installed `reccmp`, e.g. in a virtual environment.

- Install Ghidra 12.0.2 or newer.
- It may be necessary to configure the environment variable `GHIDRA_INSTALL_DIR` to point to
  your Ghidra installation. See also the
  [pyghidra documentation](https://pypi.org/project/pyghidra/).
- If there is no Ghidra project for this file yet:
  - Create a Ghidra project (either local or shared), import your original binary you want to
    decompile, analyse, and save. If this is a shared project, check in the file.
- Close any locally running Ghidra instances.
- Run one of the following commands in the directory where your `reccmp-build.yml` is located:
  - Local project:
    `reccmp-ghidra-import --target <reccmp-target> --local-project-name <ghidra-project-name> --file <file-inside-ghidra-project>`
    - If necessary, also provide `--local-project-dir`, especially if your Ghidra project is not
      located in the default directory.
  - Shared project:
    `RECCMP_GHIDRA_USER=user RECCMP_GHIDRA_PASSWORD=password reccmp-ghidra-import --target <reccmp-target> --remote-url ghidra://<host>[:<port>]/<project-name> --file <file-inside-ghidra-project>`
    - You can optionally provide `--remote-checkin-comment` if you want to customize the check-in
      comment.
    - If you know what you are doing security wise, you can also provide the username and password
      via the URL:
      `--remote-url ghidra://user:password@<host>[:<port>]/<project-name`.

## Development

- There is a [docker compose setup](./development/compose.yaml) to run a local Ghidra server for
  developing and testing the remote import functionality.
