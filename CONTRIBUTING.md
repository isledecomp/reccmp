# Contributing

Your contributions are very much appreciated! If you want to work on this tool, we recommend you do the following:
1. Set up a virtual environment in this directory.
2. Install this project within itself in editable mode: `pip install -e .`
3. Install the dev requirements: `pip install -r requirements-tests.txt`

If you also have a decompilation project, we recommend the following:
1. Set up a _separate_ virtual environment in your decompilation project.
2. Inside that virtual environment, `pip install -e path/to/your/local/reccmp/repository`.

This way, you can easily run your latest `reccmp` changes against your decompilation project.

## Testing

`isledecomp` comes with a suite of tests based on `pytest`. A number of them can be run out of the box:
```bash
pytest .
```

As of this writing, some of the tests still depend on the [Lego Island decompilation project](https://github.com/isledecomp/isle). You will need a copy of the _original_ binaries for Lego Island in order to execute all tests. This can be done by
```bash
pytest . --lego1=/path/to/LEGO1.DLL
```

## Linting and formatting

In order to keep the Python code clean and consistent, we use `pylint` and `black`:

* Run `pylint`: `pylint reccmp`
* Check formatting without making changes: `black --check reccmp`
* Apply formatting: `black reccmp`
