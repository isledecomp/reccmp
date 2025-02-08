
## Testing

`isledecomp` comes with a suite of tests. Install `requirements-tests.txt` and run it like this:

```
pip install -r requirements-tests.txt
pytest .
```

## Tool Development

In order to keep the Python code clean and consistent, we use `pylint` and `black`:

`pip install -r requirements-tests.txt`

### Run pylint (ignores build and virtualenv)

`pylint reccmp`

### Check Python code formatting without rewriting files

`black --check reccmp`

### Apply Python code formatting

`black reccmp`