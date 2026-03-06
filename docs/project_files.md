# Project Files

The configuration of `reccmp` requires three different files. As explained in the [main README](../README.md), `reccmp-project` can be used to generate each of them.

* `reccmp-project.yml` contains the main configuration. We recommend that you keep this file at the root of your repository and add it to your VCS (like `git`).
* `reccmp-user.yml` contains information that may differ from user to user, like the location of the original binary files. This file must be located in the same directory as `reccmp-project.yml`. We recommend that you ignore it from your VCS.
* `reccmp-build.yml` contains information that may differ in each recompilation, like the location of the recompiled binary and debug symbol file. We recommend that you ignore this file from your VCS.
  * If the names or paths of your build artifacts change, we recommend you generate this script as part of your build process.
  * If they do not, you can generate this file once and keep it in your build directory or at the repository root.
  * Note that as of this writing, the [plugin-based Ghidra import](../reccmp/ghidra/README.md#Setup-for-Ghidrathon) needs to have a `reccmp-build.yml` at the repository root.

## Additional information in `reccmp-project.yml`

> See the relevant [Python file](../reccmp/project/config.py) in case this documentation is outdated.

Some additional information can be added to `reccmp-project.yml` by hand. For example:

```yml
targets:
  BETA10:
    filename: BETA10.DLL
    source-root: LEGO1
    hash:
      sha256: ...
    ghidra:
      ignore-types:
        - Act2Actor
      ignore-functions:
        - 0x100f8ad0
```

This tells the Ghidra import script to ignore certain types and functions.
