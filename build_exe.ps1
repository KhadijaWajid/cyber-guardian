<#
.SYNOPSIS
    Builds the standalone desktop application CyberGuardian.exe using PyInstaller and Python 3.13.

.DESCRIPTION
    Automates clean packaging of Cyber Guardian:
    1. Validates Python 3.13 and PyInstaller environment.
    2. Cleans previous build artifacts.
    3. Executes PyInstaller against cyber_guardian.spec.
    4. Validates that dist/CyberGuardian.exe was generated.

.PARAMETER Console
    If specified, builds with the console window enabled (helpful for debugging startup).

.EXAMPLE
    .\build_exe.ps1
    .\build_exe.ps1 -Console
#>

[CmdletBinding()]
param(
    [switch]$Console
)

$ErrorActionPreference = "Stop"
$WorkspaceRoot = $PSScriptRoot

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "       Cyber Guardian Desktop Packaging Pipeline            " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Workspace : $WorkspaceRoot" -ForegroundColor DarkGray
Write-Host " Mode      : $(if ($Console) { 'Console Enabled (Debug)' } else { 'Windowed (Production)' })" -ForegroundColor DarkGray

# Ensure working directory is workspace root
Set-Location $WorkspaceRoot

# 1. Check Python 3.13
Write-Host "`n[1/4] Verifying Python 3.13 runtime..." -ForegroundColor Yellow
$pyVersion = & py -3.13 --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python 3.13 is not accessible via 'py -3.13'. Please ensure Python 3.13 is installed."
    exit 1
}
Write-Host "      Detected: $pyVersion" -ForegroundColor Green

# 2. Check PyInstaller
Write-Host "`n[2/4] Verifying PyInstaller installation..." -ForegroundColor Yellow
$pyinstallerCheck = & py -3.13 -c "import PyInstaller; print(PyInstaller.__version__)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller is missing from Python 3.13 environment. Install via: py -3.13 -m pip install pyinstaller"
    exit 1
}
Write-Host "      PyInstaller Version: $pyinstallerCheck" -ForegroundColor Green

# 3. Clean prior build artifacts
Write-Host "`n[3/4] Cleaning previous build caches..." -ForegroundColor Yellow
$TargetExe = Join-Path $WorkspaceRoot "dist\CyberGuardian.exe"
if (Test-Path "$WorkspaceRoot\build") {
    Remove-Item -Recurse -Force "$WorkspaceRoot\build" -ErrorAction SilentlyContinue
    Write-Host "      Removed: build\" -ForegroundColor DarkGray
}
if (Test-Path $TargetExe) {
    Remove-Item -Force $TargetExe -ErrorAction SilentlyContinue
    Write-Host "      Removed old: dist\CyberGuardian.exe" -ForegroundColor DarkGray
}

# Configure console environment variable if requested
if ($Console) {
    $env:PYINSTALLER_CONSOLE = "1"
} else {
    $env:PYINSTALLER_CONSOLE = "0"
}

# 4. Run PyInstaller
Write-Host "`n[4/4] Executing PyInstaller compilation..." -ForegroundColor Yellow
$SpecPath = Join-Path $WorkspaceRoot "cyber_guardian.spec"
if (-not (Test-Path $SpecPath)) {
    Write-Error "Spec file not found at: $SpecPath"
    exit 1
}

& py -3.13 -m PyInstaller --clean "$SpecPath"
if ($LASTEXITCODE -ne 0) {
    Write-Error "PyInstaller build failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

# 5. Output Verification
if (Test-Path $TargetExe) {
    $fileInfo = Get-Item $TargetExe
    $sizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host " [BUILD SUCCESS] CyberGuardian.exe generated successfully!  " -ForegroundColor Green
    Write-Host " Location : $TargetExe" -ForegroundColor White
    Write-Host " Size     : $sizeMB MB" -ForegroundColor White
    Write-Host "============================================================`n" -ForegroundColor Green
} else {
    Write-Error "Build finished but '$TargetExe' was not created."
    exit 1
}
