#!/bin/sh

# This script is used to build politeiad and politeiawww 
# including the current commit hash as a ldflag. Fetches
# hash from git log and then tries to build.

GOOS=linux
GOARCH=amd64
CGO=0
ENV="env GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=$CGO"

DIR=$(pwd)
BUILD_DIR=$DIR"/bin"

COMMIT_HASH=$(git log -1 --format='%H')

# Create bin directory for executables
[ -d $BUILD_DIR ] || mkdir BUILD_DIR

# Install pi daemon and www
cd "politeiad/"

if $($ENV go build -o $BUILD_DIR -trimpath -tags='net,go' -ldflags='-X github.com/decred/politeia/util/version.CommitHash='$COMMIT_HASH); then
    echo "Politeiad built successfully"
else
    echo "Error during d's build process"
fi

cd "../politeiawww"

if $($ENV go build -o $BUILD_DIR -trimpath -tags='net,go' -ldflags='-X github.com/decred/politeia/util/version.CommitHash='$COMMIT_HASH); then
    echo "Politeiawww built successfully"
else
    echo "Error during www's build process"
fi