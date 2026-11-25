<#
.SYNOPSIS
Builds a self-contained Windows x64 folder for a USB stick.
.DESCRIPTION
Install requirements-build.txt in the development .venv first. Target PCs need
no Python installation. -ImportLocalData copies your encrypted OTP vault and
gateway trust, and imports remembered SSH/VNC passwords into the copied vault.
The original vault and Windows credentials are preserved. Existing output
folders are never overwritten; select a new OutputPath for an updated build.
.NOTES
Build setup:
    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
    .\Build-Portable.ps1
To include your local encrypted vault and remembered passwords:
    .\Build-Portable.ps1 -ImportLocalData -OutputPath '.\dist\ECB-Personal'
#>
[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path $PSScriptRoot 'dist\ECB-Portable'),
    [string] $Username = 'mtjantzi',
    [switch] $ImportLocalData
)
$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Create .venv and install requirements-build.txt before building.'
}
$buildArguments = @((Join-Path $PSScriptRoot 'build_portable.py'), '--output', $OutputPath, '--username', $Username)
if ($ImportLocalData) {
    $buildArguments += '--import-local-data'
}
& $python @buildArguments
exit $LASTEXITCODE
