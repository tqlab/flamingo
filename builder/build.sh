#!/bin/bash

function docker_cmd() {
  DIST=$1
  CMD=$2
  mkdir -p $CACHE/$DIST/{target,registry,git,tmp}
  docker run -it --rm -v $(pwd)/..:/home/user/code \
    -v $CACHE/$DIST/target:/home/user/code/target \
    -v $CACHE/$DIST/registry:/home/user/.cargo/registry \
    -v $CACHE/$DIST/git:/home/user/.cargo/git \
    -v $CACHE/$DIST/tmp:/home/user/.cargo/tmp \
    flamingo-builder-$DIST bash -c "$CMD"
}

set -e

cd $(dirname $0)

VERSION=$(grep -e '^version =' ../Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')

mkdir -p cache/{deb}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t flamingo-builder-deb .

build_deb() {
  ARCH=$1
  TARGET=$2
  if ! [ -f ../dist/flamingo_${DEB_VERSION}_${ARCH}.deb ]; then
    docker_cmd deb "cd code && cargo deb --target ${TARGET}"
    cp $CACHE/deb/target/${TARGET}/debian/flamingo_${DEB_VERSION}-1_${ARCH}.deb ../dist/flamingo_${DEB_VERSION}_${ARCH}.deb
  fi
}

build_deb amd64 x86_64-unknown-linux-gnu