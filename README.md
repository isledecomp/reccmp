# LEGO Island Decompilation Tools

Accuracy to the game's original code is the main goal of the [decompilation project](https://github.com/isledecomp/isle). To facilitate the decompilation effort and maintain overall quality, we have devised a set of annotations, to be embedded in the source code, which allow us to automatically verify the accuracy of re-compiled functions' assembly, virtual tables, variable offsets and more.

In order for contributions to be accepted, the annotations must be used in accordance to the rules outlined here. Proper use is enforced by [GitHub Actions](/.github/workflows) which run the Python tools found in this folder. It is recommended to integrate these tools into your local development workflow as well.

# Overview

We are continually working on extending the capabilities of our "decompilation language" and the toolset around it. Some of the following annotations have not made it into formal verification and thus are not technically enforced on the source code level yet (marked as **WIP**). Nevertheless, it is recommended to use them since it is highly likely they will eventually be fully integrated.



# Tooling

Use `pip` to install the required packages to be able to use the Python tools found in this folder:

```
pip install -e .
```

All scripts will become available to use in your terminal with the `reccmp-` prefix. The example usages below assume that the retail binaries have been copied to `./legobin`.

* [`decomplint`](/reccmp/tools/decomplint.py): Checks the decompilation annotations (see above)
    * e.g. `reccmp-decomplint --module LEGO1 LEGO1`
* [`isledecomp`](/reccmp/isledecomp): A library that implements a parser to identify the decompilation annotations (see above)
* [`reccmp`](/reccmp/reccmp): Compares an original binary with a recompiled binary, provided a PDB file. For example:
    * Display the diff for a single function: `reccmp-reccmp --verbose 0x100ae1a0 legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`
    * Generate an HTML report: `reccmp-reccmp --html output.html legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`
    * Create a base file for diffs: `reccmp-reccmp --json base.json --silent legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`
    * Diff against a base file: `reccmp-reccmp --diff base.json legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`
* [`stackcmp`](/reccmp/tools/stackcmp.py): Compares the stack layout for a given function that almost matches.
    * e.g. `reccmp-stackcmp legobin/BETA10.DLL build_debug/LEGO1.DLL build_debug/LEGO1.pdb . 0x1007165d`
* [`roadmap`](/reccmp/tools/roadmap.py): Compares symbol locations in an original binary with the same symbol locations of a recompiled binary
* [`verexp`](/reccmp/tools/verexp.py): Verifies exports by comparing the exports of the original DLL and the recompiled DLL
* [`vtable`](/reccmp/tools/vtable.py): Asserts virtual table correctness by comparing a recompiled binary with the original
    * e.g. `reccmp-vtable legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`
* [`datacmp`](/reccmp/tools/datacmp.py): Compares global data found in the original with the recompiled version
    * e.g. `reccmp-datacmp legobin/LEGO1.DLL build/LEGO1.DLL build/LEGO1.PDB .`

