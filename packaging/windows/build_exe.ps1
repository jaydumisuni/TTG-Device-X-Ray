param(
    [string]$OutputDir = "dist-exe",
    [string]$PlatformToolsDir = ""
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$EntryPoint = Join-Path $ProjectRoot "packaging\windows\ttg_xray_gui.py"
$WorkPath = Join-Path $ProjectRoot "build\pyinstaller-xray"
$SpecPath = Join-Path $ProjectRoot "build\pyinstaller-spec"
$Destination = Join-Path $ProjectRoot $OutputDir
$RequiredPlatformTools = @("adb.exe", "fastboot.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")

function Test-PlatformToolsDirectory([string]$Path) {
    if (-not $Path -or -not (Test-Path $Path -PathType Container)) { return $false }
    foreach ($required in $RequiredPlatformTools) {
        $candidate = Join-Path $Path $required
        if (-not (Test-Path $candidate -PathType Leaf) -or (Get-Item $candidate).Length -le 0) {
            return $false
        }
    }
    return $true
}

function Resolve-PlatformToolsDirectory {
    $candidates = @()
    if ($PlatformToolsDir) { $candidates += $PlatformToolsDir }
    if ($env:ANDROID_SDK_ROOT) { $candidates += (Join-Path $env:ANDROID_SDK_ROOT "platform-tools") }
    if ($env:ANDROID_HOME) { $candidates += (Join-Path $env:ANDROID_HOME "platform-tools") }
    $candidates += @(
        "D:\mibu-build-tools\android-sdk\platform-tools",
        "D:\mibu-build-tools\platform-tools",
        (Join-Path $ProjectRoot "platform-tools")
    )
    foreach ($candidate in $candidates | Select-Object -Unique) {
        if (Test-PlatformToolsDirectory $candidate) {
            return (Resolve-Path $candidate).Path
        }
    }
    return $null
}

if (!(Test-Path $EntryPoint)) {
    throw "Missing Qt executable entry point: $EntryPoint"
}

$ResolvedPlatformTools = Resolve-PlatformToolsDirectory
if (-not $ResolvedPlatformTools) {
    throw "Android platform-tools are required for the standalone X-Ray EXE. Set ANDROID_SDK_ROOT/ANDROID_HOME, pass -PlatformToolsDir, or install them at D:\mibu-build-tools\android-sdk\platform-tools."
}

New-Item -ItemType Directory -Force -Path $Destination | Out-Null
New-Item -ItemType Directory -Force -Path $WorkPath | Out-Null
New-Item -ItemType Directory -Force -Path $SpecPath | Out-Null

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
    "--specpath", $SpecPath
)

foreach ($required in $RequiredPlatformTools) {
    $source = Join-Path $ResolvedPlatformTools $required
    $arguments += @("--add-binary", "$source;platform-tools")
}
$arguments += $EntryPoint

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

Write-Host "Platform-tools bundled from: $ResolvedPlatformTools"
Write-Host "Included: $($RequiredPlatformTools -join ', ')"
Write-Host "Built standalone Qt executable: $Executable"
Write-Host "Size: $Size bytes"
