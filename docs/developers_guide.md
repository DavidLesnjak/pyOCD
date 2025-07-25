---
title: Developers’ guide
---

<div class="alert alert-info">
<p>
Please familiarise yourself with the <a href="https://github.com/pyocd/pyOCD/blob/main/CONTRIBUTING.md">
contributing guide</a> before beginning any development on pyOCD or related projects.
</p>
</div>

## Setup

PyOCD developers are strongly recommended to setup a working environment using either
[virtualenv](https://virtualenv.pypa.io/en/latest/) or the built-in `venv` module (only use of `venv` is shown
below, but the two are equivalent). After cloning the code, you can setup a virtualenv and install the pyOCD
dependencies for the current platform by following the detailed steps below.

Install the necessary tools listed below. Skip any step where a compatible tool already exists.

* [Install Python](https://www.python.org/downloads/) version 3.8.0 or above. Add to PATH.
    *  Note that on Windows, the 32-bit Python 2.7 must be installed for the Python-enabled `arm-none-eabi-gdb-py` to
        work properly and for the `test/gdb_test.py` functional test to pass.
* [Install Git](https://git-scm.com/downloads). Add to PATH.
* [Install GNU Arm Embedded toolchain](https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-rm).
    This provides `arm-none-eabi-gdb` used for testing the gdbserver. Add to PATH.

## Steps

**Step 1.** Get the sources and create a virtual environment

```
$ git clone https://github.com/pyocd/pyOCD
$ cd pyOCD
$ python3 -m venv venv
```

**Step 2.** Activate virtual environment

Activate your virtualenv and install the pyOCD dependencies for the current platform by doing
the following.

Linux or Mac:
```
$ source venv/bin/activate
```

Windows:
```
$ venv\Scripts\activate
```

**Step 3.** Install editable pyOCD

```
$ pip install -e .[test]
```

If you switch branches, you may need to reinstall.

Because the `develop` branch doesn't have version tags except older tags from the `develop` branch point,
the version number of pyOCD might be significantly out of date. If this is an issue, you can override the
version by setting the `SETUPTOOLS_SCM_PRETEND_VERSION` environment variable to the desired version number
(without a "v" prefix).

**Step 4.** Develop

See the [porting guide]({% link _docs/adding_new_targets.md %}) for how to add new devices. Of course, we welcome
all improvements and changes. See the [contributor statement](https://github.com/pyocd/pyOCD/blob/main/CONTRIBUTING.md) for some guidelines.

See the [branch policy](#branch-configuration-policy) below for details about branches and which branch you should
work from.

If you'd like suggestions for something to work on, from small to large, the
[Slack](https://join.slack.com/t/pyocd/shared_invite/zt-zqjv6zr5-ZfGAXl_mFCGGmFlB_8riHA) workspace is a great
way to engage with the community and maintainers.

**Step 5.** Test

See the [automated test documentation]({% link _docs/automated_tests.md %}) for an introduction to available tests and related scripts.

To run the unit tests, you can execute the following.

```
$ pytest
```

The automated test suite also needs to be run:

```
$ cd test
$ python ./automated_test.py
```

**Step 6.** Pull request

Once you are satisfied with your changes and all automated tests pass, please create a
[new pull request](https://github.com/pyocd/pyOCD/pull/new) on GitHub to share your work. Please see below for
which branch to target.

Pull requests should be made after a changeset is
[rebased](https://www.atlassian.com/git/tutorials/merging-vs-rebasing/workflow-walkthrough).


## Branch configuration policy

There are two primary branches:

- `main`: Stable branch reflecting the most recent release. May contain bug fixes not yet released, but no new
    feature commits are allowed.
- `develop`: Active development branch for the next minor version. Merged into `main` at release time.

There may be other development branches present to host long term development of major new features and backwards incompatible changes, such as API changes.

The branch that your changes should be made against depends on the type and complexity of the changes:

- Only a bug fix: please target `main`.
- Any other changes, or a mix of changes: target the `develop` branch. This is also a good choice if you aren't sure.

Maintainers will cherry-pick commits between `main` and `develop` as necessary to keep fixes in sync.

If you have any questions about how best to submit changes or the branch policy, please ask in the
[Slack](https://join.slack.com/t/pyocd/shared_invite/zt-zqjv6zr5-ZfGAXl_mFCGGmFlB_8riHA) workspace or
[GitHub Discussions](https://github.com/pyocd/pyOCD/discussions). We'll be happy to help.


## Debugging pyOCD

### VS Code

Debugging pyOCD launched by VS Code is straightforward, and is much like debugging any package.

1. First, set up the pyOCD development and virtualenv as described above.

2. Set up the launch config as follows.

    - Set `pythonPath` to the python executable in the virtualenv.

    - Set `module` to `pyocd.__main__`, to debug pyOCD entry point as a module. This works better than trying to debug the script `.../pyocd/__main__.py` as it ensures the relative module references inside pyOCD work correctly..

    For instance, here is a VS Code launch config for pyOCD's gdbserver:

        {
            "name": "pyocd gdbserver",
            "type": "python",
            "request": "launch",
            "module": "pyocd.__main__",
            "console": "integratedTerminal",
            "stopOnEntry": true,
            "pythonPath": "/Users/username/projects/pyOCD/venv/bin/python3",
            "showReturnValue": true,
            "args": ["gdb", "-v"]
        }


It's also possible to debug pyOCD remotely. This is useful either for cases where it is launched by another tool and you cannot directly control the command line , or is on another machine.

For remote debug, use a launch config like this:

        {
            "name": "Python: Attach using port",
            "type": "python",
            "request": "attach",
            "port": 5678,
        }

If the pyOCD process is on another machine, add a `host` key to the launch config with the host name. (This defaults to localhost.)

Install [debugpy](https://github.com/microsoft/debugpy/) with pip into your virtual environment.

To remotely debug pyOCD from the command line, run it with the `debugpy` module. For instance, `python -m debugpy --listen 5678 -m pyocd gdb -v`. Additionally, `--wait-for-client` can be added after the port number to wait for the debug client to connect before running pyOCD.

If you don't control pyOCD's launch, then `debugpy` can be called directly from pyOCD's code. Add the following code to pyocd. Inside `pyocd.__main__.PyOCDTool.run()` is a good location, though it can be done at module level in `__main__.py`.

```py
import debugpy
debugpy.listen(5678)
```

To pause pyOCD's execution and wait for the debug client to connect, add this line as well:
```py
debugpy.wait_for_client()
```




