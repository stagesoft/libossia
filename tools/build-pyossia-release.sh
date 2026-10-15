#!/bin/bash
# Build the CUEMS pyossia release artifacts on Debian 12 (bookworm), the
# production OS: python3-pyossia_<debian version>_amd64.deb and
# pyossia-<PEP 440 version>-cp311-cp311-linux_x86_64.whl, from one build.
# The version comes from src/ossia-python/debian/changelog; see
# src/ossia-python/README.md "CUEMS fork: versioning and releases".
#
# Usage: tools/build-pyossia-release.sh [output dir]
#   default output dir: build/pyossia-release
#   ALLOW_DIRTY=1  build despite uncommitted changes to tracked files
#                  (test builds only: the artifacts no longer match a commit)
#
# Needs docker. The checkout is mounted read-only and copied inside the
# container, so the build never writes into the working tree.

set -euo pipefail

IMAGE=debian:bookworm

if [[ "${1:-}" != --in-container ]]; then
  REPO=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
  OUT=$(realpath -m "${1:-$REPO/build/pyossia-release}")

  if [[ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]]; then
    if [[ "${ALLOW_DIRTY:-}" != 1 ]]; then
      echo "ERROR: uncommitted changes to tracked files; commit them, or set" \
           "ALLOW_DIRTY=1 for a test build" >&2
      exit 1
    fi
    echo "WARNING: dirty tree, these artifacts match no commit" >&2
  fi

  mkdir -p "$OUT"
  echo "Building $(git -C "$REPO" describe --tags --always --dirty) on $IMAGE" \
       "into $OUT (logs: $OUT/*.log)"
  docker run --rm \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -v "$REPO":/src:ro -v "$OUT":/out \
    "$IMAGE" bash /src/tools/build-pyossia-release.sh --in-container
  ls -1 "$OUT"/*.deb "$OUT"/*.whl
  exit 0
fi

# --- inside the container -------------------------------------------------

trap 'chown -R "${HOST_UID}:${HOST_GID}" /out' EXIT

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential cmake git ca-certificates pkg-config \
  python3 python3-dev python3-setuptools python3-wheel \
  debhelper dh-python devscripts fakeroot \
  > /out/apt.log

git config --global --add safe.directory '*'

# Copy the checkout (with .git and submodules) so the build stays out of /src.
mkdir -p /work
tar -C /src --exclude=./build --exclude=./dist -cf - . | tar -C /work -xf -
# Modules prebuilt on the host must not end up in the package.
rm -f /work/src/ossia-python/pyossia/*.so
cd /work

cmake -B build -S . -DOSSIA_PYTHON_ONLY=1 -DOSSIA_CI=1 \
  -DCMAKE_BUILD_TYPE=Release -DPYTHON_EXECUTABLE=/usr/bin/python3 \
  > /out/configure.log 2>&1
cmake --build build -j"$(nproc)" > /out/build.log 2>&1
# The install step builds the wheel and copies the module into
# src/ossia-python/pyossia/, where dpkg-buildpackage picks it up.
cmake --build build --target install > /out/install.log 2>&1
cp build/src/ossia-python/dist/*.whl /out/

cd src/ossia-python
dpkg-buildpackage -b -us -uc > /out/deb.log 2>&1
cp ../python3-pyossia_*.deb /out/
