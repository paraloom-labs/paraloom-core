@echo off
echo Starting Paraloom Windows Validator...
echo.
echo Coordinator: 192.168.1.15:9001
echo Validator: This machine on port 9002
echo.

set RUST_LOG=info
paraloom-node.exe start --config config/windows-validator.toml

pause
