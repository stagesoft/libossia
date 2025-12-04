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
