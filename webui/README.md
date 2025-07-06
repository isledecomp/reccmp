# Web UI support files
This directory contains tests and config files used to validate the HTML output from `reccmp`. When you run `reccmp-reccmp` with the `--html` option, we create a file with the compared entities for the specified target. The page has some interactive elements that allow you to filter entities and inspect the diff if there is one.

The HTML file is created as follows:
1. Load the contents of `template.html` and `reccmp.js` from `reccmp/assets`.
2. Insert the contents of `reccmp.js` into a `<script>` element in `template.html`.
3. Using the completed analysis run, create a serialized report file in JSON format, then insert its contents in a second `<script>` element in `template.html`. The result is that the data is assigned to the `report` variable.
The `pystache` module is used to combine these elements into the final output file.

## Setup
The tools in this directory require [node.js](https://nodejs.org/). The `package.json` file lists the dependencies and you can use your package manager of choice to install them. For example: `npm install`.

## Formatting and linting
[Biome](https://biomejs.dev/) validates the test files and javascript source. You can run it yourself with the command: `npm run lint`.

Biome has additional command line options that will auto-correct some syntax issues.

## End-to-end tests
[Playwright](https://playwright.dev/) runs the end-to-end tests on the HTML output file.

The first step is to create the test subject. The included file `testdata.json` is the basis for the HTML output used in the tests. To create the `index.html` file, use the `reccmp-aggregate` command from the `webui` directory as follows:
```
reccmp-aggregate --samples ./testdata.json ./testdata.json --html ./index.html
```
The next step is to install the browser binaries used to run the tests. This is a one-time requirement. The command is: `npx playwright install --with-deps`

Finally, to run the tests, use the command `npm run e2e`. You can launch the interactive test runner with the command `npm run e2e-ui`.
