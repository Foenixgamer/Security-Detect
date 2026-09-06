# Empaqueta la GUI como ejecutable standalone con PyInstaller.
#
# Requisitos previos:
#   pip install -r requirements-dev.txt        (incluye pyinstaller)
#
# Uso:
#   powershell -ExecutionPolicy Bypass -File scripts\build_exe.ps1
#
# Resultado: dist\SQS-GUI.exe  (ejecutar con SQS-GUI.exe --app)
param(
    [string]$Python = "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"
)

$ErrorActionPreference = "Stop"
Set-Location -Path (Split-Path $PSScriptRoot -Parent)

& $Python -m PyInstaller --noconfirm --onefile --windowed `
    --name "SQS-GUI" `
    --add-data "config;config" `
    --add-data "data;data" `
    --add-data "rules;rules" `
    --add-data "layers;layers" `
    sqs_gui.py

Write-Host "OK -> dist\SQS-GUI.exe  (usar SQS-GUI.exe --app)"