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

TOOLCHAIN=$(grep -e '^toolchain =' ../Cargo.toml | sed -e 's/toolchain = "\(.*\)"/\1/')
UPX_VERSION=$(grep -e '^upx_version =' ../Cargo.toml | sed -e 's/upx_version = "\(.*\)"/\1/')

VERSION=$(grep -e '^version =' ../Cargo.toml | sed -e 's/version = "\(.*\)"/\1/')
DEB_VERSION=$(echo "$VERSION" | sed -e 's/-/~/g')
if echo "$VERSION" | fgrep -q "-"; then
  RPM_VERSION=$(echo "$VERSION" | sed -e 's/-/-0./g')
else
  RPM_VERSION="$VERSION-1"
fi

mkdir -p cache/{rpm,deb,musl}
CACHE=$(pwd)/cache

mkdir -p ../dist

docker build --rm -f=Dockerfile-deb -t flamingo-builder-deb .

# x86_64 deb
if ! [ -f ../dist/flamingo_${DEB_VERSION}_amd64.deb ]; then
  docker_cmd deb 'cd code && cargo deb'
  cp $CACHE/deb/target/debian/flamingo_${DEB_VERSION}_amd64.deb ../dist/flamingo_${DEB_VERSION}_amd64.deb
fi

build_deb() {
  ARCH=$1
  TARGET=$2
  if ! [ -f ../distflamingo_${DEB_VERSION}_${ARCH}.deb ]; then
    docker_cmd deb "cd code && cargo deb --target ${TARGET}"
    cp $CACHE/deb/target/${TARGET}/debian/flamingo_${DEB_VERSION}_${ARCH}.deb ../dist/flamingo_${DEB_VERSION}_${ARCH}.deb
  fi
}

build_deb i386 i686-unknown-linux-gnu

docker build --rm -f=Dockerfile-musl -t flamingo-builder-musl .

build_static() {
  ARCH=$1
  TARGET=$2
  if ! [ -f ../dist/flamingo_${VERSION}_static_${ARCH} ]; then
    docker_cmd musl "cd code && cargo build --release --target ${TARGET} && upx --lzma target/${TARGET}/release/flamingo"
    cp $CACHE/musl/target/${TARGET}/release/flamingo ../dist/flamingo_${VERSION}_static_${ARCH}
  fi
}

build_static amd64 x86_64-unknown-linux-musl
