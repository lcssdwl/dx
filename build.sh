#!/usr/bin/env bash
set -euo pipefail

export CGO_ENABLED=0

echo "Building Windows amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dx-server-windows-amd64.exe .

echo "Building Linux amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dx-server-linux-amd64 .

echo "Building Linux arm64..."
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o dx-server-linux-arm64 .

echo "Done."
