# CSV import

`reccmp` has the option to parse [comma-separated value (CSV)](https://en.wikipedia.org/wiki/Comma-separated_values) files and load data to supplement code annotations on the original binary.

Any metadata set from a CSV file will overwrite the same data from code annotations on the same address.

If the same address is repeated on multiple lines the same CSV file, or across multiple files, the metadata will be overwritten each time.

## Motivation

The CSV feature is optional. In most situations, we can gather enough information to run analysis and provide a diff for each function using only the code annotations and PDB.

However, loading data via CSV allows the user to specify all aspects of entity metadata, including attributes like the entity size, which is not currently possible with code annotations.

You may find it helpful to copy data from Ghidra and use it to bootstrap a new decomp project. For example: CRT or library functions.

## Setup

Add the list of CSV files under the `data-sources` key for the target in `reccmp-project.yml`. For example:

```yml
targets:
  ISLE:
    filename: ISLE.EXE
    source-root: .
    hash:
      sha256: 5cf57c284973fce9d14f5677a2e4435fd989c5e938970764d00c8932ed5128ca
    data-sources:
      - test.csv
```

The paths are relative to the directory that contains `reccmp-project.yml`.

## Format

Here's an example of a CSV file using the pipe character as the delimiter.

```csv
address|name|size
1008b400|_atol|164
1008b4b0|_atoi|14
1008b4c0|_strtok|216
1008b5a0|_sprintf|103
1008b608|__ftol|39
```

The header on the first line defines the columns used in the file. The only required column is `"address"`. It does not need to appear first, but this is common.

The address value is always interpreted as a hexadecimal number, even if only digits 0-9 appear. You can use the typical `0x` prefix but it was omitted for this example. The `h` suffix sometimes seen in assembly code is not supported.

The `"name"` field is the name for the entity, as you would expect. `"size"` is the number of bytes used by the entity in virtual memory. This is always interpreted as a decimal number.

`"type"` expects one of these values:

- `function, template, synthetic, library, stub` for function entities
- `global`
- `string`
- `widechar`
- `float`
- `vtable`

These are the same categories used in the [code annotations](./annotations.md). `LINE` is not yet supported in CSV.

### Finer points

For a delimiter, you can use a comma, the pipe, or a tab. These files are called CSV even when the delimiter is not the comma.

Do not include padding whitespace around the columns or try to align the values.

If there is no value for the given column, you can leave it blank, as in this example where `0x10001070` has a null type:

```csv
address|type|size
0x10001000|function|92
0x10001070||25
0x10001090|function|10
```

If the value contains the delimiter, one approach is to wrap the entire thing in double quotes. For example, in this entity name that contains a comma:

```csv
address,name
101310a0,"set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >::set<MxAtom *,MxAtomCompare,allocator<MxAtom *> >"
```

You can also escape the delimiter or double quote character with a backslash as needed. For example, one way to get the strings `"hello world"` followed by two ways to get `"hello, world"`:

```csv
address,name
10001000,\"hello world\"
10002000,"\"hello, world\""
10003000,\"hello\, world\"
```

If you need to escape the _escape character_, use two backslashes, as in:

```csv
address,name
10004000,te\\st
```

### Non-standard syntax

CSV does not support comments, but we allow them. Any line that begins with `//` or `#` will be skipped.

```txt
address,type

# Months of the year
100db57c,string
100db588,string
100db594,string

# Days of the week
100db614,string
100db620,string
100db628,string
```

Blank lines are ignored entirely.

### Column reference

These fields can appear in the CSV file:

| column | description | possible values |
| ------ | ----------- | --------------- |
| `address` | Address of the entity. Required. | Hex number with or without `0x` prefix |
| `name` | Name for the entity (e.g. the fully-qualified function name) | text |
| `symbol` | Linker name | text |
| `type` | Entity type | one of: `function, template, synthetic, library, stub, global, string, widechar, float, vtable` |

All other fields are ignored.
