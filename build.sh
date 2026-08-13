#!/bin/bash

set -e
export CGO_ENABLED=0

# The version comes from the VERSION file, which is embedded in the binary, so
# it cannot drift from what the release is called. Commit and build date are
# baked in here because the build machine is the only thing that knows them.
# This script builds every platform for local use; the release workflow ships
# linux only.
VERSION=$(tr -d ' \t\r\n' < VERSION)
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X goproxy/pkg/proxy.commit=$COMMIT"
LDFLAGS="$LDFLAGS -X goproxy/pkg/proxy.buildDate=$BUILD_DATE"

ROOT=$(pwd)

# Every archive holds a single goproxy-$VERSION/ directory, so unpacking one
# never scatters files over whatever the user happened to be standing in.
package() {
	local goos="$1" goarch="$2" binary="goproxy"
	[ "$goos" = windows ] && binary="goproxy.exe"

	local staging="build/$goos-$goarch"
	local dir="$staging/goproxy-$VERSION"
	rm -rf "$staging"
	mkdir -p "$dir/config-examples"

	GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$LDFLAGS" -o "$dir/$binary" ./cli
	cp LICENSE README.md "$dir/"
	cp examples/*.yaml examples/README.md "$dir/config-examples/"
	# systemd is linux only, so shipping the unit anywhere else is noise
	if [ "$goos" = linux ]; then
		cp packaging/goproxy.service "$dir/"
	fi

	if [ "$goos" = windows ]; then
		(cd "$staging" && zip -qr "$ROOT/bin/goproxy-$VERSION-$goos-$goarch.zip" "goproxy-$VERSION")
	else
		tar -C "$staging" -czf "bin/goproxy-$VERSION-$goos-$goarch.tar.gz" "goproxy-$VERSION"
	fi
	echo "bin/goproxy-$VERSION-$goos-$goarch"
}

rm -rf bin build
mkdir -p bin
package linux amd64
package linux arm64
package darwin amd64
package darwin arm64
package windows amd64
package windows arm64
rm -rf build

cd bin
artefacts=$(ls)
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum $artefacts > checksums.txt
else
	shasum -a 256 $artefacts > checksums.txt
fi
cd ..
