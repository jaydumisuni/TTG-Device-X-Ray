param(
    [string]$OutputDir = "dist-exe"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EntryPoint = Join-Path $ProjectRoot "packaging\windows\ttg_xray_gui.py"
$WorkPath = Join-Path $ProjectRoot "build\pyinstaller-xray"
$SpecPath = Join-Path $ProjectRoot "build\pyinstaller-spec"
$Destination = Join-Path $ProjectRoot $OutputDir

if (!(Test-Path $EntryPoint)) {
    throw "Missing Qt executable entry point: $EntryPoint"
}

New-Item -ItemType Directory -Force -Path $Destination | Out-Null

$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--clean",
    "--onefile",
    "--windowed",
    "--noupx",
    "--name", "TTG-Device-XRay",
    "--paths", (Join-Path $ProjectRoot "src"),
    "--collect-data", "ttg_device_xray",
    "--hidden-import", "PySide6.QtSvg",
    "--hidden-import", "PySide6.QtNetwork",
    "--distpath", $Destination,
    "--workpath", $WorkPath,
    "--specpath", $SpecPath,
    $EntryPoint
)

Push-Location $ProjectRoot
try {
    & python @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}

$Executable = Join-Path $Destination "TTG-Device-XRay.exe"
if (!(Test-Path $Executable)) {
    throw "Expected executable was not created: $Executable"
}

$Size = (Get-Item $Executable).Length
if ($Size -lt 10000000) {
    throw "Executable is unexpectedly small ($Size bytes); refusing to publish it."
}

Write-Host "Built standalone Qt executable: $Executable"
Write-Host "Size: $Size bytes"
