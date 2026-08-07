#!/bin/sh
set -eu

expected_version=${1:?usage: verify-release.sh VERSION}
exec go run ./cmd/releasecheck -dist dist -version "$expected_version"
