# Reccmp Decompilation Toolchain

[![Discord server](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.gg/aSKCSXwpNp)
[![Matrix channel](https://badgen.net/badge/icon/matrix?icon=matrix&label)](https://matrix.to/#/#isledecomp:matrix.org)

`reccmp` (recompilation compare) is a collection of tools for decompilation projects. It was born from the [decompilation of LEGO Island](https://github.com/isledecomp/isle). Functions and data are matched based on comments in the source code. For example:

```cpp
// FUNCTION: LEGO1 0x100b12c0
MxCore* MxObjectFactory::Create(const char* p_name)
{
  // implementation
}
```

This allows you to automatically verify the accuracy of functions, virtual tables, variable offsets and more. [Click to see the full syntax](docs/annotations.md).

You can supplement the code annotations with metadata from CSV files. See the [instructions and syntax](docs/csv.md).

At the moment, C++ compiled to 32-bit x86 with old versions of MSVC (like 4.20) is supported. Work on support for newer MSVC versions is in progress - testing and bug reports are greatly appreciated. Other compilers, languages and architectures are not supported at the moment, but feel free to contribute if you wish to do so!

## Getting started

### Installing / upgrading `reccmp`

1. (Recommended) Set up and activate a virtual Python environment in the directory of your recompilation project (this is different for different operating systems and shells).
2. Install `reccmp`: `pip install reccmp`

The next steps differ based on what kind of project you have.

### Contributing to a project that already uses `reccmp`

1. Compile the C++ project.
2. Run `reccmp-project detect --search-path "path/to/folder/with/original/binaries"`.
3. If there is no `reccmp-build.yml` after building: Navigate to the recompiled binaries folder and run `reccmp-project detect --what recompiled`.
4. Look into `reccmp-project.yml` to see what the target is called.
5. Run `reccmp-reccmp --target <YOURTARGET>`. You should see a list of functions and others together with their match percentage.

### Setting up an existing decompilation project that has not used `reccmp` before

1. Run `reccmp-project create --originals "path/to/original" --scm`. This generates two files `reccmp-project.yml` and `reccmp-user.yml`; the latter will automatically be added to the `.gitignore`.
2. Annotate one function of your existing project as shown above and recompile. Note that the recompiled binary should have the same name file name as the original.
3. Navigate to your recompiled binary and run `reccmp-project detect --what recompiled`. A file `reccmp-build.yml` will be generated. This file should also be user-specific (see below on how to auto-generate this file by the build toolchain).
4. Look into `reccmp-project.yml` to see what the target is called.
5. Run `reccmp-reccmp --target <YOURTARGET>` from the same directory. If all goes well, you will see match percentage of the function you annotated above.

### Fresh project

1. Run `reccmp-project create --originals "path/to/original/binary" ["path/to/second/original/binary"] --cmake-project`
2. You will see a lot of new files. Set up your C++ compiler and compile the project defined by `CMakeLists.txt`, ideally into a sub-directory like `./build`. Advice on building with old MSVC versions can be found at the [LEGO Island Decompilation project](https://github.com/isledecomp/isle).
3. Look into `reccmp-project.yml` to see what the target is called.
4. Navigate to the build directory and run `reccmp-reccmp --target <YOURTARGET>`.

### Config files

See the [documentation on the config files](./docs/project_files.md) for more information.

## Tooling

All scripts will become available to use in your terminal with the `reccmp-` prefix. Note that these scripts need to be executed in the directory where `reccmp-build.yml` is located.

* [`aggregate`](/reccmp/tools/aggregate.py): Combines JSON reports into a single file.
  * Aggregate using highest accuracy score: `reccmp-aggregate --samples ./sample0.json ./sample1.json ./sample2.json --output ./combined.json`
  * Diff two saved reports: `reccmp-aggregate --diff ./before.json ./after.json`
  * Diff against the aggregate: `reccmp-aggregate --samples ./sample0.json ./sample1.json ./sample2.json --diff ./before.json`
* [`decomplint`](/reccmp/tools/decomplint.py): Checks the decompilation annotations (see above)
  * e.g. `reccmp-decomplint --target LEGO1`
* [`reccmp`](/reccmp/tools/asmcmp.py): Compares an original binary with a recompiled binary, provided a PDB file. For example:
  * Display the diff for a single function: `reccmp-reccmp --target LEGO1 --verbose 0x100ae1a0`
  * Generate an HTML report: `reccmp-reccmp --target LEGO1 --html output.html`
  * Create a base file for diffs: `reccmp-reccmp --target LEGO1 --json base.json --silent`
  * Diff against a base file: `reccmp-reccmp --target LEGO1 --diff base.json`
  * Reuse the dump of an unchanged PDB between runs: `reccmp-reccmp --target LEGO1 --cache` (see below)
* [`stackcmp`](/reccmp/tools/stackcmp.py): Compares the stack layout for a given function that almost matches.
  * e.g. `reccmp-stackcmp --target BETA10 0x1007165d`
* [`roadmap`](/reccmp/tools/roadmap.py): Compares symbol locations in an original binary with the same symbol locations of a recompiled binary
* [`verexp`](/reccmp/tools/verexp.py): Verifies exports by comparing the exports of the original DLL and the recompiled DLL
* [`vtable`](/reccmp/tools/vtable.py): Asserts virtual table correctness by comparing a recompiled binary with the original
  * e.g. `reccmp-vtable --target LEGO1`
* [`datacmp`](/reccmp/tools/datacmp.py): Compares global data found in the original with the recompiled version
  * e.g. `reccmp-datacmp --target LEGO1`


### Caching the cvdump output

Most of the time a `reccmp-reccmp` run spends is `cvdump.exe` dumping the debug
information of the PDB, and the text it produces depends only on the PDB and
the options we ask for. Runs that compare the same build again -- saving a base
file, then diffing against it, then looking at one function -- repeat that work
every time.

`--cache` keeps the dump and reuses it while the PDB is unchanged. On one
OpenSHC build (a 12 MB PDB, 25 MB of dump text) a run goes from 5.3 s to 2.8 s.

The cache is **off by default**, deliberately: an entry that is wrongly
considered valid would have reccmp report a comparison against a binary that no
longer exists, and being slow is better than being wrong. An entry is used only
when all of the following are unchanged since it was written:

* the size and modification time of the PDB,
* the set of cvdump options, and
* the size and modification time of the bundled `cvdump.exe`.

Anything else -- no entry, an entry this version of reccmp does not understand,
an unreadable file -- is treated as a miss, and the dump is made again. The
entry is keyed on the PDB path and the option set, so a rebuild replaces its own
entry rather than filling the disk, and a dump is stored only once it has been
read to the end, so an interrupted run cannot leave a truncated dump behind to
be mistaken for a complete one.

`--invalidate-cache` runs `cvdump.exe` even if an entry exists and replaces it;
use it if you have reason to think a cached dump is wrong. It implies `--cache`.

Entries are written to `$XDG_CACHE_HOME/reccmp` (`%LOCALAPPDATA%\reccmp\Cache`
on Windows), or to `$RECCMP_CACHE_DIR` if you set it. They are plain text and
safe to delete at any time.

## Ghidra Import

We also have tooling to import the information from the decompilation into [Ghidra](https://github.com/NationalSecurityAgency/ghidra). See the relevant [README](reccmp/ghidra/README.md) for additional information.

## Best practices

We have established some [best practices](docs/recommendations.md) that have no impact on `reccmp`'s output, but have made a positive impact on the LEGO Island decompilation.

[`cydifflib`](https://github.com/rapidfuzz/CyDifflib) is a drop-in replacement for Python's builtin [`difflib`](https://docs.python.org/3/library/difflib.html) module that offers better performance. If `cydifflib` is installed in the environment where you run `reccmp`, we will use it.

## Contributing

Feel free to contribute to this project if you are interested! More information can be found at [CONTRIBUTING.md](./CONTRIBUTING.md).
