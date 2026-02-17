# Contributing

Your contributions are very much appreciated! If you want to work on this tool, we recommend you do the following:

1. Set up a virtual environment in this directory.
2. Install project and test dependencies: `uv sync --group test`

If you also have a decompilation project, we recommend the following:

1. Set up a _separate_ virtual environment in your decompilation project.
2. Inside that virtual environment, `uv pip install -e path/to/your/local/reccmp/repository`.

This way, you can easily run your latest `reccmp` changes against your decompilation project.

## Testing

This project comes with a suite of tests based on `pytest`. Most of them can be run out of the box:

```bash
uv run pytest .
```

The remaining tests depend on existing _original_ binary files, specifically:

* `LEGO1.DLL` from _LEGO Island_ (English, v1.1), see e.g. <https://www.legoisland.org/wiki/LEGO_Island#Download>.
* `SKI.EXE` from _SkiFree_ (16 bit), see e.g. <https://github.com/isledecomp/reccmp/pull/90>.

It is recommended to place the original binaries under `tests/binfiles`. Alternatively, you can specify their directory as follows:

```bash
uv run pytest . --binfiles=/path/to/the/binfiles
```

## Linting and formatting

In order to keep the Python code clean and consistent, we use `pylint` and `black`:

* Run `pylint`: `uv run pylint reccmp`
* Check formatting without making changes: `uv run black --check reccmp`
* Apply formatting: `uv run black reccmp`
