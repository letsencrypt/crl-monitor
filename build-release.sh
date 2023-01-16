#!/bin/bash
set -euxo pipefail

# Build the pair of zip files to upload to lambda

mkdir -p build
DIR=$(mktemp -d "build/build-$(git rev-parse --short HEAD)-XXXXXX")
echo "Building in $DIR"

# Churner is just a binary
mkdir -p "$DIR/churner"
go build -o "$DIR/churner/churner" lambda/churner/churner.go
# zip
pushd "$DIR/churner"
zip churner.zip churner
popd
cp "$DIR/churner.zip" build/churner.zip


# Checker binary and certs
mkdir -p "$DIR/checker"
go build -o "$DIR/checker/checker" lambda/checker/checker.go

# Include all the issuers
# TODO(#23): Don't bake these into the release
cp checker/testdata/*.pem "$DIR/checker/"

# zip
pushd "$DIR/checker"
zip checker.zip checker ./*.pem
popd
cp "$DIR/checker.zip" build/checker.zip

echo "built: build/churner.zip build/checker.zip"
