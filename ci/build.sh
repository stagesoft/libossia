#!/bin/bash -ex
# Note : to make the tests work under travis, they have to be changed in order not to require QApplication but only QCoreApplication

source ${0%/*}/codesign_functions.sh

case "$TRAVIS_OS_NAME" in
  linux)
    export CMAKE_BIN=$(readlink -f "$(find cmake-latest/bin -name cmake -type f )")
    if [[ "$PYTHON_VERSION" == "2.7" ]]; then
      export PYTHON_BIN=$(which python)
    else
      export PYTHON_BIN=$(which python3)
    fi
  ;;
  osx)
    export CMAKE_BIN=$(which cmake)
    if [[ "$PYTHON_VERSION" == "2.7" ]]; then
      export PYTHON_BIN=/usr/local/bin/python2
    else
      export PYTHON_BIN=/usr/local/bin/python3
    fi
  ;;
esac

export CTEST_OUTPUT_ON_FAILURE=1

if [[ "$BUILD_TYPE" == Rpi* ]]; then
  #setup some environment variable to help CMAKE to find libraries for crosscompiling
  export RPI_ROOT_PATH=/opt/cross-pi-gcc-8.2.0
  export PKG_CONFIG_SYSROOT_DIR=$RPI_ROOT_PATH
  export PKG_CONFIG_LIBDIR=${RPI_ROOT_PATH}/usr/lib/pkgconfig:${RPI_ROOT_PATH}/usr/share/pkgconfig:${RPI_ROOT_PATH}/usr/lib/arm-linux-gnueabihf/pkgconfig/
  export PATH=/opt/cross-pi-gcc/bin:${PATH}
  export LD_LIBRARY_PATH=/opt/cross-pi-gcc/lib:${LD_LIBRARY_PATH}
fi

mkdir -p ${ARTIFACTS_DIR}

mkdir build
cd build

case "$TRAVIS_OS_NAME" in
  linux)
    if [[ -f /usr/bin/gcc-9 ]] ; then
      export CC=/usr/bin/gcc-9
      export CXX=/usr/bin/g++-9
    elif [[ -f /usr/bin/gcc-8 ]] ; then
      export CC=/usr/bin/gcc-8
      export CXX=/usr/bin/g++-8
    elif [[ -f /usr/bin/gcc-7 ]] ; then
      export CC=/usr/bin/gcc-7
      export CXX=/usr/bin/g++-7
    else
      export CC=/usr/bin/gcc-6
      export CXX=/usr/bin/g++-6
    fi
#    export VERBOSE=1
    QT_ENV_SCRIPT=$(find /opt -name 'qt*-env.sh')
    set +e
    source $QT_ENV_SCRIPT
    set -e
    export LD_LIBRARY_PATH="/usr/lib64:$LD_LIBRARY_PATH"

    case "$BUILD_TYPE" in
      Debug)
        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
          -DOSSIA_STATIC=$OSSIA_STATIC \
          -DOSSIA_TESTING=1 \
          -DOSSIA_EXAMPLES=1 \
          -DOSSIA_CI=1 \
          -DPORTAUDIO_ONLY_DYNAMIC=1 \
          -DOSSIA_QT=1 \
          -DOSSIA_PD=0 \
          -DOSSIA_CPP=1 \
          -DOSSIA_C=1 \
          ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target ExperimentalTest

      ;;
      Release)
        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/install" \
          -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
          -DOSSIA_C=1 \
          -DOSSIA_CPP=1 \
          -DOSSIA_STATIC=$OSSIA_STATIC \
          -DOSSIA_TESTING=1 \
          -DOSSIA_EXAMPLES=0 \
          -DOSSIA_DATAFLOW=0 \
          -DOSSIA_EDITOR=0 \
          -DOSSIA_PROTOCOL_AUDIO=0 \
          -DOSSIA_PD=0 \
          -DOSSIA_CI=1 \
          -DPORTAUDIO_ONLY_DYNAMIC=1 \
          -DOSSIA_QT=0 ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target ExperimentalTest
        $CMAKE_BIN --build . --target install


        if [[ "$OSSIA_STATIC" == "1" ]]; then
          cd $TRAVIS_BUILD_DIR/install
          tar -czf ${ARTIFACTS_DIR}/libossia-native-linux_x86_64-static.tar.gz include lib
        else
          cd $TRAVIS_BUILD_DIR/install
          tar -czf ${ARTIFACTS_DIR}/libossia-native-linux_x86_64.tar.gz include lib
        fi

      ;;
      ossia-cpp)

        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/install" \
          -DCMAKE_BUILD_TYPE=Release \
          -DOSSIA_TESTING=0 \
          -DOSSIA_EXAMPLES=0 \
          -DOSSIA_STATIC=0 \
          -DOSSIA_CI=1 \
          -DOSSIA_CPP_ONLY=1 ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/install
        tar -czf ${ARTIFACTS_DIR}/libossia-cpp-linux_x86_64.tar.gz *

      ;;
      PdTest)

        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
                   -DCMAKE_CXX_COMPILER="$CXX" \
                   -DCMAKE_BUILD_TYPE=Debug \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DOSSIA_TESTING=1 \
                   -DOSSIA_EXAMPLES=0 \
                   -DOSSIA_PD_ONLY=1 \
                   -DOSSIA_CI=1 \
                   ..


        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        pushd "$TRAVIS_BUILD_DIR/3rdparty/pure-data"
          sudo apt-get install -qq autoconf libtool
          ./autogen.sh
          ./configure
          make -j 2
          sudo make install
        popd

        mkdir -p ~/pd-externals/
        mv "$TRAVIS_BUILD_DIR/ossia-pd-package/ossia" ~/pd-externals/

        $CMAKE_BIN --build . --target test

      ;;
      PdRelease)

        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
                   -DCMAKE_CXX_COMPILER="$CXX" \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DOSSIA_PD_ONLY=1 \
                   -DOSSIA_CI=1 \
                   ..

        # make a clone after initializing submodules (with Cmake)
        # and before build
        pushd /tmp
          git clone ${TRAVIS_BUILD_DIR} --recursive
          tar -czf ${ARTIFACTS_DIR}/libossia-source.tar.gz --exclude .git libossia
          rm -rf libossia
        popd

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/ossia-pd-package
        tar -czf ${ARTIFACTS_DIR}/ossia-pd-linux_x86_64.tar.gz ossia

        $TRAVIS_BUILD_DIR/ci/push_deken.sh
      ;;
      PurrDataRelease)

        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
                   -DCMAKE_CXX_COMPILER="$CXX" \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DOSSIA_PD_ONLY=1 \
                   -DOSSIA_PURR_DATA=1 \
                   -DOSSIA_CI=1 \
                   ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/ossia-pd-package
        tar -czf ${ARTIFACTS_DIR}/ossia-purr-data-linux_x86_64.tar.gz ossia

      ;;
      RpiPdRelease)

        $CMAKE_BIN -DCMAKE_TOOLCHAIN_FILE="$PWD/../cmake/toolchain/arm-linux-gnueabihf.cmake" \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DOSSIA_CI=1 \
                   -DOSSIA_PD_ONLY=1 \
                   ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/ossia-pd-package
        tar -czf ${ARTIFACTS_DIR}/ossia-pd-linux_arm.tar.gz ossia

        $TRAVIS_BUILD_DIR/ci/push_deken.sh
      ;;
      RpiPurrdataRelease)

        $CMAKE_BIN -DCMAKE_TOOLCHAIN_FILE="$PWD/../cmake/toolchain/arm-linux-gnueabihf.cmake" \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DOSSIA_CI=1 \
                   -DOSSIA_PD_ONLY=1 \
                   -DOSSIA_PURR_DATA=1 \
                   ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/ossia-pd-package
        tar -czf ${ARTIFACTS_DIR}/ossia-purr-data-linux_arm.tar.gz ossia
      ;;
      RpiPythonRelease)

        # _version.py is not valid in a non-git folder
        # When making a wheel, we write the git tag which it has been build from
        # request the version
        WHEEL_TAG_VERSION=$(echo -e "import sys\nsys.path.append('${TRAVIS_BUILD_DIR}/src/ossia-python/')\nfrom pyossia._version import get_versions\nget_versions()['version']" | ${PYTHON_BIN})
        echo "#! /usr/bin/env python
# -*- coding: utf-8 -*-

def get_versions():
  return {'version':'${WHEEL_TAG_VERSION}'}" > ${TRAVIS_BUILD_DIR}/src/ossia-python/pyossia/_version.py
        $CMAKE_BIN -DCMAKE_TOOLCHAIN_FILE="$PWD/../cmake/toolchain/arm-linux-gnueabihf.cmake" \
                   -DPYTHON_INCLUDE_DIR=${RPI_ROOT_PATH}/usr/include/python${PYTHON_VERSION} \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                   -DPYTHON_EXECUTABLE=${PYTHON_BIN} \
                   -DOSSIA_CI=1 \
                   -DOSSIA_PYTHON_ONLY=1 \
                   ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        if [[ "x${TRAVIS_TAG}" != "x" ]]; then
          ${PYTHON_BIN} -m twine upload -u ${PyPiUser} -p ${PyPiWord} ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl || true
        fi
        cp ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl ${ARTIFACTS_DIR}/
      ;;
      RpiRelease)

        $CMAKE_BIN -DCMAKE_TOOLCHAIN_FILE="$PWD/../cmake/toolchain/arm-linux-gnueabihf.cmake" \
                   -DOSSIA_PD=0 \
                   -DCMAKE_BUILD_TYPE=Release \
                   -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/install" \
                   -DOSSIA_STATIC=$OSSIA_STATIC \
                   -DOSSIA_TESTING=0 \
                   -DOSSIA_EXAMPLES=0 \
                   -DOSSIA_CI=1 \
                   -DOSSIA_QT=0 \
                   -DOSSIA_PYTHON=0 \
                   -DOSSIA_C=1 \
                   -DOSSIA_CPP=1 \
                   ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/install
        if [[ "$OSSIA_STATIC" ==  "1" ]]; then
          tar -czf ${ARTIFACTS_DIR}/libossia-native-linux_arm-static.tar.gz *
        else
          tar -czf ${ARTIFACTS_DIR}/libossia-native-linux_arm.tar.gz *
        fi
      ;;
      Rpi-ossia-cpp)
        $CMAKE_BIN -DCMAKE_TOOLCHAIN_FILE="$PWD/../cmake/toolchain/arm-linux-gnueabihf.cmake" \
             -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/install" \
             -DOSSIA_CI=1 \
             -DOSSIA_CPP_ONLY=1 \
             ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd $TRAVIS_BUILD_DIR/install
        tar -czf ${ARTIFACTS_DIR}/ossia-cpp-linux_arm.tar.gz *
      ;;
      python_manylinux)
        # _version.py is not valid in a non-git folder
        # When making a wheel, we write the git tag which it has been build from
        # request the version
        WHEEL_TAG_VERSION=$(echo -e "import sys\nsys.path.append('${TRAVIS_BUILD_DIR}/src/ossia-python/')\nfrom pyossia._version import get_versions\nget_versions()['version']" | ${PYTHON_BIN})
        echo "#! /usr/bin/env python
# -*- coding: utf-8 -*-

def get_versions():
  return {'version':'${WHEEL_TAG_VERSION}'}" > ${TRAVIS_BUILD_DIR}/src/ossia-python/pyossia/_version.py

        docker run --rm -v `pwd`:/ $DOCKER_IMAGE $PRE_CMD ci/build-wheels.sh

        ls wheelhouse/
        cp wheelhouse/*.whl ${ARTIFACTS_DIR}/

      ;;
      python)
        # _version.py is not valid in a non-git folder
        # When making a wheel, we write the git tag which it has been build from
        # request the version
        WHEEL_TAG_VERSION=$(echo -e "import sys\nsys.path.append('${TRAVIS_BUILD_DIR}/src/ossia-python/')\nfrom pyossia._version import get_versions\nget_versions()['version']" | ${PYTHON_BIN})
        echo "#! /usr/bin/env python
# -*- coding: utf-8 -*-

def get_versions():
  return {'version':'${WHEEL_TAG_VERSION}'}" > ${TRAVIS_BUILD_DIR}/src/ossia-python/pyossia/_version.py
        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/ossia-python" \
          -DPYTHON_EXECUTABLE=${PYTHON_BIN} \
          -DOSSIA_CI=1 \
          -DOSSIA_PYTHON_ONLY=1 \
          ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        # now we just want to install the wheel and run the tests
        ${PYTHON_BIN} -m pip install --user ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl
        ${PYTHON_BIN} ${TRAVIS_BUILD_DIR}/src/ossia-python/tests/test.py

        if [[ "x${TRAVIS_TAG}" != "x" ]]; then
          ${PYTHON_BIN} -m twine upload -u ${PyPiUser} -p ${PyPiWord} ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl || true
        fi

        ${PYTHON_BIN} ${TRAVIS_BUILD_DIR}/src/ossia-python/tests/test.py

        cp ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl ${ARTIFACTS_DIR}/

      ;;
      qml)
        $CMAKE_BIN -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_BUILD_TYPE=Release \
          -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR/ossia-qml" \
          -DOSSIA_CI=1 \
          -DOSSIA_QML_ONLY=1 \
          ..

        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target install

        cd "$TRAVIS_BUILD_DIR/ossia-qml"
        tar -czf ${ARTIFACTS_DIR}/ossia-qml-linux_x86_64.tar.gz Ossia
      ;;
      RpiDocker)
        echo "Building for Rpi in Docker"
        docker run -it  -v $TRAVIS_BUILD_DIR/ci/docker.sh:/docker.sh iscore/iscore-rpi-sdk /bin/bash /docker.sh
      ;;
      Coverage)
        $CMAKE_BIN \
          -DCMAKE_C_COMPILER="$CC" \
          -DCMAKE_CXX_COMPILER="$CXX" \
          -DCMAKE_BUILD_TYPE=Debug \
          -DOSSIA_TESTING=1 \
          -DOSSIA_COVERAGE=1 \
          -DPORTAUDIO_ONLY_DYNAMIC=1 \
          -DOSSIA_PD=0 \
          -DOSSIA_QT=1 \
          -DOSSIA_C=1 \
          ..
        $CMAKE_BIN --build . -- -j2
        $CMAKE_BIN --build . --target ossia_coverage
        rm -rf **/*.o
        coveralls-lcov coverage.info
      ;;
      Docs)
        cd ../docs/Doxygen

        doxygen > doxygen.log
        (
            # inspired from generateDocumentationAndDeploy.sh, Jeroen de Bruijn
            git clone -b gh-pages https://git@$GH_REPO_REF
            cd "$GH_REPO_NAME"
            git checkout --orphan dummy
            git branch -D gh-pages
            git checkout --orphan gh-pages

            echo "$(pwd)"

            # Set the push default to simple i.e. push only the current branch.
            git config --global push.default simple
            # Pretend to be an user called Travis CI.
            git config user.name "Travis CI"
            git config user.email "travis@travis-ci.org"

            rm -rf *

            echo "" > .nojekyll
            mv ../html .

            if [ -d "html" ] && [ -f "html/index.html" ]; then
                echo "Commiting..."
                git add --all
                git commit -m "Deploy code docs to GitHub Pages Travis build: ${TRAVIS_BUILD_NUMBER}" -m "Commit: ${TRAVIS_COMMIT}"
                git push --force "https://${GH_REPO_TOKEN}@${GH_REPO_REF}"
            fi


        )
      ;;
    esac
  ;;

  osx)
    export QT_PATH=$(dirname $(dirname $(find /usr/local/Cellar/qt -name Qt5Config.cmake) ) )
    export CXX=clang++
    export CMAKE_PREFIX_PATH="$QT_PATH"

    export CMAKE_BIN=$(which cmake)

    if [[ "$BUILD_TYPE" == "PdRelease" ]]; then

      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
               -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
               -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
               -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
               -DOSSIA_CI=1 \
               -DOSSIA_PD_ONLY=1 \
               -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
               -DOSSIA_OSX_FAT_LIBRARIES=1 \
               ..
      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install
      echo List TRAVIS_BUILD_DIR content
      cd $TRAVIS_BUILD_DIR
      ls

      release_macos_folder "$TRAVIS_BUILD_DIR/ossia-pd-package/ossia" "ossia-pd-data-osx.zip" "io.ossia.ossia-puredata"
      $TRAVIS_BUILD_DIR/ci/push_deken.sh

    elif [[ "$BUILD_TYPE" == "PurrDataRelease" ]]; then

      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
               -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
               -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
               -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
               -DOSSIA_CI=1 \
               -DOSSIA_PD_ONLY=1 \
               -DOSSIA_PURR_DATA=ON \
               -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
               -DOSSIA_OSX_FAT_LIBRARIES=1 \
               ..
      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install
      echo List TRAVIS_BUILD_DIR content
      cd $TRAVIS_BUILD_DIR
      ls

      release_macos_folder "$TRAVIS_BUILD_DIR/ossia-pd-package/ossia" "ossia-purr-data-osx.zip" "io.ossia.ossia-purrdata"

    elif [[ "$BUILD_TYPE" == "PdTest" ]]; then

      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Debug \
               -DOSSIA_SANITIZE=0 \
               -DOSSIA_TESTING=1 \
               -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
               -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
               -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
               -DOSSIA_CI=1 \
               -DOSSIA_PD_ONLY=1 \
               -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
               -DOSSIA_OSX_FAT_LIBRARIES=1 \
               ..
      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install

      mkdir -p ~/Documents/Pd/externals
      mv $TRAVIS_BUILD_DIR/ossia-pd-package/ossia ~/Documents/Pd/externals

      export PD_VERSION=0.48-2
      wget http://msp.ucsd.edu/Software/pd-$PD_VERSION.mac.tar.gz
      tar xf pd-$PD_VERSION.mac.tar.gz
      export PATH="${PWD}/Pd-$PD_VERSION.app/Contents/Resources/bin:${PATH}"

      echo "Test Pd loading on MacOS"
      pd -path "${HOME}/Documents/Pd/externals" -nogui -lib ossia 2>&1 -send "pd quit;"

      $CMAKE_BIN --build . --target test

    elif [[ "$BUILD_TYPE" == "MaxRelease" ]]; then
      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
               -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
               -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
               -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
               -DOSSIA_CI=1 \
               -DOSSIA_MAX_ONLY=1 \
               -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
               ..
      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install
      echo List TRAVIS_BUILD_DIR content
      cd $TRAVIS_BUILD_DIR
      ls
      
      release_macos_folder "$TRAVIS_BUILD_DIR/ossia-max-package/ossia" "ossia-max-osx.zip" "io.ossia.ossia-max"

    elif [[ "$BUILD_TYPE" == "python" ]]; then
      # _version.py is not valid in a non-git folder
      # When making a wheel, we write the git tag from which it has been build
      PEP440_VERSION=$(echo $TRAVIS_TAG | sed s/^[^0-9]*//g)

      echo "#! /usr/bin/env python
# -*- coding: utf-8 -*-

def get_versions():
  return {'version':'${PEP440_VERSION}'}" > ${TRAVIS_BUILD_DIR}/src/ossia-python/pyossia/_version.py
      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
                 -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
                 -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR" \
                 -DPYTHON_EXECUTABLE=${PYTHON_BIN} \
                 -DPYTHON_LIBRARY=/usr/local/opt/python/Frameworks/Python.framework/Versions/${python}/lib/libpython${python}.dylib \
                 -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
                 -DOSSIA_CI=1 \
                 -DOSSIA_PYTHON_ONLY=1 \
                 -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
                 ..

      $CMAKE_BIN --build . -- -j2
      codesign_osx "$TRAVIS_BUILD_DIR"
      $CMAKE_BIN --build . --target install
      codesign_osx "$TRAVIS_BUILD_DIR"

      # now we just want to install the wheel and run the tests
      ${PYTHON_BIN} -m pip install --user ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl
      ${PYTHON_BIN} ${TRAVIS_BUILD_DIR}/src/ossia-python/tests/test.py

      if [[ "x${TRAVIS_TAG}" != "x" ]]; then
          ${PYTHON_BIN} -m twine upload -u ${PyPiUser} -p ${PyPiWord} ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl || true
          mv ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl ${ARTIFACTS_DIR}/
      fi
      cp ${TRAVIS_BUILD_DIR}/build/src/ossia-python/dist/pyossia*.whl ${ARTIFACTS_DIR}/
    elif [[ "$BUILD_TYPE" == "qml" ]]; then
      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
                 -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
                 -DCMAKE_INSTALL_PREFIX="$TRAVIS_BUILD_DIR"/ossia-qml \
                 -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
                 -DOSSIA_CI=1 \
                 -DOSSIA_QML_ONLY=1 \
                 -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
                 ..
      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install
      
      release_macos_folder "$TRAVIS_BUILD_DIR/ossia-qml/Ossia" "ossia-qml-osx.zip" "io.ossia.ossia-qml"

    elif [[  "$BUILD_TYPE" == "ossia-cpp" ]]; then
      $CMAKE_BIN -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
        -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
        -DOSSIA_TESTING=0 \
        -DOSSIA_EXAMPLES=0 \
        -DOSSIA_STATIC=0 \
        -DOSSIA_CI=1 \
        -DCMAKE_INSTALL_PREFIX=$TRAVIS_BUILD_DIR/libossia \
        -DOSSIA_CPP_ONLY=1 ..

      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target install

      release_macos_folder "$TRAVIS_BUILD_DIR/libossia" "ossia-cpp-osx.zip" "io.ossia.ossia-cpp"

    else
      $CMAKE_BIN -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
               -DOSSIA_STATIC=$OSSIA_STATIC \
               -DOSSIA_TESTING=1 \
               -DOSSIA_EXAMPLES=1 \
               -DCMAKE_PREFIX_PATH="$CMAKE_PREFIX_PATH" \
               -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
               -DOSSIA_CI=1 \
               -DOSSIA_QT=0 \
               -DOSSIA_DATAFLOW=0 \
               -DOSSIA_EDITOR=0 \
               -DOSSIA_PROTOCOL_AUDIO=0 \
               -DOSSIA_C=1 \
               -DOSSIA_CPP=1 \
               -DOSSIA_OSX_RETROCOMPATIBILITY=1 \
               -DCMAKE_INSTALL_PREFIX=$TRAVIS_BUILD_DIR/libossia \
               -DOSSIA_PD=0 \
               ..

      $CMAKE_BIN --build . -- -j2
      $CMAKE_BIN --build . --target ExperimentalTest
      $CMAKE_BIN --build . --target install

      if [[ "$BUILD_TYPE" == "Release" ]]; then
        if [[ "$OSSIA_STATIC" == "1" ]]; then
          zip -r ${ARTIFACTS_DIR}/libossia-native-macos-static.zip "$TRAVIS_BUILD_DIR/libossia"
        else
          release_macos_folder "$TRAVIS_BUILD_DIR/libossia" "libossia-native-osx.zip" "io.ossia.ossia-native"
        fi
      fi
    fi
  ;;
esac
