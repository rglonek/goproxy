#!/bin/bash

set -e
export CGO_ENABLED=0

# version, commit and build date are baked into the binary, so `goproxy
# -version` reports what was actually built instead of a string somebody has to
# remember to edit.
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X goproxy/pkg/proxy.version=${VERSION#v}"
LDFLAGS="$LDFLAGS -X goproxy/pkg/proxy.commit=$COMMIT"
LDFLAGS="$LDFLAGS -X goproxy/pkg/proxy.buildDate=$BUILD_DATE"

build() {
	local goos="$1" goarch="$2" out="$3"
	rm -rf goproxy goproxy.exe
	GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="$LDFLAGS" -o "$out" ./cli
}

rm -rf bin
mkdir -p bin
build linux amd64 goproxy
tar -zcvf bin/goproxy-linux-amd64.tar.gz goproxy
build linux arm64 goproxy
tar -zcvf bin/goproxy-linux-arm64.tar.gz goproxy
build darwin amd64 goproxy
tar -zcvf bin/goproxy-darwin-amd64.tar.gz goproxy
build darwin arm64 goproxy
tar -zcvf bin/goproxy-darwin-arm64.tar.gz goproxy
build windows amd64 goproxy.exe
zip bin/goproxy-windows-amd64.zip goproxy.exe
build windows arm64 goproxy.exe
zip bin/goproxy-windows-arm64.zip goproxy.exe
rm -rf goproxy goproxy.exe

cd bin
artefacts=$(ls)
if command -v sha256sum >/dev/null 2>&1; then
	sha256sum $artefacts > checksums.txt
else
	shasum -a 256 $artefacts > checksums.txt
fi
cd ..
