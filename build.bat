@echo off
setlocal
chcp 65001 >nul

echo Building Windows amd64...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags="-s -w" -o dx-server-windows-amd64.exe . || goto :fail

echo Building Linux amd64...
set GOOS=linux
set GOARCH=amd64
go build -trimpath -ldflags="-s -w" -o dx-server-linux-amd64 . || goto :fail

echo Building Linux arm64...
set GOARCH=arm64
go build -trimpath -ldflags="-s -w" -o dx-server-linux-arm64 . || goto :fail

echo Done.
exit /b 0

:fail
echo Build failed.
exit /b 1
