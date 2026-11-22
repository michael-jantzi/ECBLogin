<#
.SYNOPSIS
Opens a local SSH tunnel to the VNC desktop assigned by Pascal.
.DESCRIPTION
Signs in once, obtains the verification code from ECB_Dept_AuthCode in
%LOCALAPPDATA%\ECB\otp.kdbx, runs vncconnect, and prints the viewer address.
On first use, enter your passwords at the prompts. A successful SSH login saves
them in Windows Credential Manager for your Windows account on this computer.
Later logins use those passwords and get a fresh verification code from KeePassXC.
When vncconnect starts a desktop on its assigned host, the script answers the
department password prompt and gets a separate verification code if requested.
It waits for a new code if KeePassXC still shows the one used for Pascal.
Startup continues while Pascal sends progress. After 90 seconds without output,
the script reports a timeout.
Leave this window open while using VNC. Press Ctrl+C to disconnect.
.PARAMETER LocalPort
Port on 127.0.0.1 for your VNC viewer. Defaults to 5905.
.PARAMETER Username
Department login. Defaults to mtjantzi.
.PARAMETER PasswordEntry
Optional path to the KeePassXC entry holding the department password in
otp.kdbx. With this option, only the vault password is saved in Credential Manager.
.PARAMETER RefreshPasswords
Prompt again and replace the saved passwords after a successful SSH login.
If you use PasswordEntry, edit the department password in KeePassXC.
.EXAMPLE
.\Connect-ECB.ps1
.EXAMPLE
.\Connect-ECB.ps1 -LocalPort 5910 -PasswordEntry 'Department/SSH'
.EXAMPLE
.\Connect-ECB.ps1 -RefreshPasswords
.NOTES
To set up a fresh copy, run these commands from the project folder with Python 3.10 or newer:
    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install -r requirements.txt
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int] $LocalPort = 5905,

    [ValidateNotNullOrEmpty()]
    [string] $Username = 'mtjantzi',

    [string] $PasswordEntry,

    [switch] $RefreshPasswords
)

$python = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw 'Set up the project from this folder with "python -m venv .venv" followed by ".\.venv\Scripts\python.exe -m pip install -r requirements.txt".'
}

$loginArguments = @('--username', $Username, '--local-port', $LocalPort)
if ($PasswordEntry) {
    $loginArguments += @('--password-entry', $PasswordEntry)
}
if ($RefreshPasswords) {
    $loginArguments += '--refresh-passwords'
}
& $python (Join-Path $PSScriptRoot 'ecb_login.py') @loginArguments
exit $LASTEXITCODE
