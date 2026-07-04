# dissect.disc

A Dissect module implementing a parser for file systems commonly used on optical media, such as ISO9660 and several extensions. For more
information, please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.disc/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.disc` is available on [PyPI](https://pypi.org/project/dissect.disc/).

```bash
pip install dissect.disc
```

This module is also automatically installed if you install the `dissect` package.

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

`dissect.disc` is developed and released as open source in collaboration with Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc (<https://www.nccgroup.com>).

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
