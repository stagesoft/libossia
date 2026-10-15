# CUEMS fork: versioning and releases

This branch (`cuems`) is the CUEMS fork of libossia. Every build of pyossia
made from it is a CUEMS-specific build and carries a `cuems` revision, both in
the Debian package and in the Python wheel.

## Single version source

The newest entry of [`debian/changelog`](debian/changelog) is the version of
the build. Nothing else is edited by hand:

* `dpkg-buildpackage` reads it for the `.deb` version.
* `setup.py` reads it for the wheel version and freezes it into the built
  `pyossia/_version.py`, so an installed copy reports it as
  `pyossia.__version__` (git-derived versions are no longer used).

**Every build that changes shipped code gets a new changelog entry first.**
Never build or publish a different binary under a version that already
exists: apt and pip treat equal versions as the same package and will not
replace one with the other. (`2.0.0-rc6+124+cuems2` was published twice with
different contents; `cuems3` exists to end that ambiguity.)

## Version scheme

| Line | Debian version | Wheel version (PEP 440) | Git tag |
|---|---|---|---|
| Current, upstream 2.0.0 rc6 | `2.0.0-rc6+124+cuemsN` | `2.0.0rc6+124.cuems.N` | `v2.0.0-rc6+124+cuemsN` |
| Next stable, first release | `2.0.1-cuems` | `2.0.1+cuems` | `v2.0.1-cuems` |
| Next stable, later builds | `2.0.1-cuemsN` | `2.0.1+cuems.N` | `v2.0.1-cuemsN` |

In `2.0.0-rc6+124+cuemsN`, `2.0.0-rc6` is the upstream release, `+124` the
upstream git snapshot the fork is based on, and `cuemsN` the fork revision.

**The next stable version is `2.0.1-cuems`, not `2.0.0`.** dpkg splits the
current versions at the last hyphen into upstream `2.0.0` and revision
`rc6+124+cuemsN`, which sorts above any numeric revision, so a plain
`2.0.0-1` would install as a *downgrade*. Moving the upstream part to `2.0.1`
sorts above every `2.0.0-*` build regardless of revision. Checked with
`dpkg --compare-versions`:

```
2.0.1-cuems   > 2.0.0-rc6+124+cuems3
2.0.1-cuems1  > 2.0.1-cuems
2.0.1-cuems10 > 2.0.1-cuems9
```

Mapping to PEP 440 (implemented in `setup.py`, `pep440_version`): a
pre-release revision (`rcN`, `aN`, `bN`) joins the public version, any other
revision and every `+part` go to the local label, and a trailing number is
split into its own segment (`cuems3` → `cuems.3`). The split is required:
PEP 440 compares a mixed segment as text, so `cuems10` would sort below
`cuems9`. Local labels cannot be uploaded to PyPI; wheels are published on
GitHub releases only.

## Release procedure

1. Add the new entry on top of `debian/changelog` and commit it.
2. Tag that commit `v<debian version>`, e.g. `v2.0.0-rc6+124+cuems3`.
3. Build the `.deb` and the wheel from the tagged commit **on Debian 12
   (bookworm)**, the production OS, e.g. in a `debian:bookworm` container.
   A build on a newer system links against a newer glibc/libstdc++ and fails
   to import on bookworm. Both artifacts come out of one build, which
   [`tools/build-pyossia-release.sh`](../../tools/build-pyossia-release.sh)
   runs in a `debian:bookworm` container (output in `build/pyossia-release/`);
   it refuses a checkout with uncommitted changes. The steps it performs:
   ```bash
   cmake -B build -S . -DOSSIA_PYTHON_ONLY=1 -DOSSIA_CI=1 \
       -DCMAKE_BUILD_TYPE=Release -DPYTHON_EXECUTABLE=/usr/bin/python3
   cmake --build build -j"$(nproc)"
   cmake --build build --target install    # wheel: build/src/ossia-python/dist/
   cd src/ossia-python && dpkg-buildpackage -b -us -uc   # deb: src/
   ```
4. Create the GitHub release named and tagged `v<debian version>` and attach
   `python3-pyossia_<debian version>_amd64.deb` and
   `pyossia-<wheel version>-cp311-cp311-linux_x86_64.whl`.

# Build tips

* First do a git clone according to the procedure here: https://github.com/ossia/libossia/wiki/Building
* Then go to the root libossia folder
* Create a build folder and go inside
* Run one of the following commands:

## For Python 3 using `pyenv` and minimal compilation

* A new `-DOSSIA_PYTHON_ONLY=1` flag is been introduced to allow for a minimal compilation of the library.

Compilation using `pyenv` allows for multiple version targets on the same machine.

This method has been able to run on debian systems for Python v3.9.25 (buster), v3.11.9 (bookworm), v3.13.9 (trixie)


```bash
# e.g. for python 3.11.9, adapt using `ls -l ${HOME}/.pyenv/versions`
cmake .. -DOSSIA_PYTHON_ONLY=1 \
    -DCMAKE_INSTALL_PREFIX=ossia-install \
    -DPYTHON_LIBRARY=${HOME}/.pyenv/versions/3.11.9/lib/libpython3.11.so \
    -DPYTHON_EXECUTABLE=${HOME}/.pyenv/versions/3.11.9/bin/python3.11 \
    -DPYTHON_INCLUDE_DIR=${HOME}/.pyenv/versions/3.11.9/include/python3.11
make -j8 -B
make install

# wheel will be available at src/ossia-python/dist/
```

# Old versions

The following versions are no longer maintained and are not recommended.
Wheel creation may need a downgraded `versioneer.py` file. Old version can be recovered from the repository root using:

`git checkout 66fab31a663ac469a2034cc01cacb3a194732d09 -- src/ossia-python/versioneer.py`


## For Python 3.6
`cmake .. -DPYTHON_EXECUTABLE=/usr/local/bin/python3 -DPYTHON_LIBRARY=/usr/local/opt/python3/Frameworks/Python.framework/Versions/3.6/lib/libpython3.6.dylib -DOSSIA_PYTHON=1`

## For Python 2
`cmake .. -DPYTHON_EXECUTABLE=/usr/local/bin/python -DPYTHON_LIBRARY=/usr/local/opt/python/Frameworks/Python.framework/Versions/2.7/lib/libpython2.7.dylib -DOSSIA_PYTHON=1`

## build options
`OSSIA_PROTOCOL_HTTP:BOOL=ON`    
`OSSIA_PROTOCOL_MIDI:BOOL=ON`    
`OSSIA_PROTOCOL_OSCQUERY:BOOL=ON`    
`OSSIA_PROTOCOL_SERIAL:BOOL=OFF`    
`OSSIA_PROTOCOL_WEBSOCKETS:BOOL=OFF`   
