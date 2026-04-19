# Reccmp Decompilation Toolchain

[![Discord server](https://badgen.net/badge/icon/discord?icon=discord&label)](https://discord.gg/aSKCSXwpNp)
[![Matrix channel](https://badgen.net/badge/icon/matrix?icon=matrix&label)](https://matrix.to/#/#isledecomp:matrix.org)

`reccmp` (recompilation compare) is a collection of tools for decompilation projects. Functions and data are matched based on comments in the source code. For example:

```cpp
// FUNCTION: GAME 0x100b12c0
MxCore* MxObjectFactory::Create(const char* p_name)
{
  // implementation
}
```

This allows you to automatically verify the accuracy of functions, virtual tables, variable offsets and more.

Full documentation available on [our GitHub page](https://github.com/isledecomp/reccmp/).
