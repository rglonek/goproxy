#!/bin/bash

set -e
export CGO_ENABLED=0
rm -rf bin
mkdir -p bin
rm -rf goproxy goproxy.exe
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o goproxy cli/main.go
tar -zcvf bin/goproxy-linux-amd64.tar.gz goproxy
rm -rf goproxy goproxy.exe
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o goproxy cli/main.go
tar -zcvf bin/goproxy-linux-arm64.tar.gz goproxy
rm -rf goproxy goproxy.exe
GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o goproxy cli/main.go
tar -zcvf bin/goproxy-darwin-amd64.tar.gz goproxy
rm -rf goproxy goproxy.exe
GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o goproxy cli/main.go
tar -zcvf bin/goproxy-darwin-arm64.tar.gz goproxy
rm -rf goproxy goproxy.exe
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o goproxy.exe cli/main.go
zip bin/goproxy-windows-amd64.zip goproxy.exe
rm -rf goproxy goproxy.exe
GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o goproxy.exe cli/main.go
zip bin/goproxy-windows-arm64.zip goproxy.exe
rm -rf goproxy goproxy.exe
