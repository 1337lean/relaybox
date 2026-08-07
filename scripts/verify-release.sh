#!/bin/sh
set -eu

expected_version=${1:?usage: verify-release.sh VERSION}
expected_binary_version=${expected_version#v}
verify_dir=$(mktemp -d)
cleanup() {
	rm -rf "$verify_dir"
}
trap cleanup EXIT INT TERM

archive_count=0
for archive in dist/*.tar.gz; do
	test -f "$archive"
	archive_count=$((archive_count + 1))
	tar -tzf "$archive" | grep -Eq '(^|/)LICENSE$'
	tar -tzf "$archive" | grep -Eq '(^|/)README.md$'
done
for archive in dist/*.zip; do
	test -f "$archive"
	archive_count=$((archive_count + 1))
	unzip -Z1 "$archive" | grep -Eq '(^|/)LICENSE$'
	unzip -Z1 "$archive" | grep -Eq '(^|/)README.md$'
done
test "$archive_count" -gt 0

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
case $(uname -m) in
	x86_64) host_arch=amd64 ;;
	arm64 | aarch64) host_arch=arm64 ;;
	*) echo "unsupported verification architecture" >&2; exit 1 ;;
esac
host_archive=$(find dist -maxdepth 1 -type f -iname "*${host_os}*${host_arch}*.tar.gz" -print -quit)
test -n "$host_archive"
tar -xzf "$host_archive" -C "$verify_dir"
binary=$(find "$verify_dir" -type f -name relaybox -print -quit)
test -n "$binary"
test "$("$binary" version)" = "relaybox $expected_binary_version"

(cd dist && sha256sum --check checksums.txt)
