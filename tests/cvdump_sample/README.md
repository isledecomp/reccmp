## `cvdump` text samples

The .txt files in this directory contain output from the `TYPES` section of `cvdump`. See `__init__.py` for instructions on how to use the files in a test.

Separating sample data from the tests solves many problems for us:

1. Mocking `cvdump` data by hand is tricky and prone to inaccuracy. It is much easier to create the scenario you want to test in code and use real `cvdump` data.
2. Having no limit to the length of `cvdump` data means we can isolate each test scenario rather than construct a monolith sample to use with many tests.
3. Leaf ids have no intrinsic significance. The tests read better when we can call out "the id for class X" rather than use a magic number.

### Creating a sample

The `cpp` subdirectory contains the source file used to create a PDB and generate the sample with a similar name. Unless specified, the compiler was MSVC 4.20. (MSVC 6.0 has equivalent output in all cases as of September 2026.) Compiler flags: `/W3 /Od /Zi`.

You can use `reccmp-cvdump` or `cvdump.exe` to create a sample from the PDB.

The expected format for the sample file is:
1. Aliases and type keys separated by a single space. Type keys must be in hex format with 0x prefix.
2. Blank line.
3. Text from the `TYPES` section.

For example:
```
alias-1 0x1000
alias-2 0x1001

0x1000 : Length = 10, Leaf = 0x1002 LF_POINTER
...
```
