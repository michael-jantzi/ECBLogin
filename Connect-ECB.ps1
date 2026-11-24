<#
.SYNOPSIS
Opens the VNC desktop assigned by Pascal in RealVNC Viewer.
.DESCRIPTION
Signs in once, obtains the verification code from ECB_Dept_AuthCode in
%LOCALAPPDATA%\ECB\otp.kdbx, and runs vncconnect. Once the SSH tunnel is ready,
the script opens RealVNC Viewer for the local address. It uses a matching saved
Viewer profile when available. The default address is 127.0.0.1:5905.
On first use, enter your department and vault passwords at the terminal prompts.
A successful SSH login saves them in Windows Credential Manager. When prompted
for the VNC desktop password, enter the password you set with vncconnect.
The script saves it separately for your department username after Viewer
confirms the VNC login. Future runs supply it automatically through a private
Windows pipe. Classic VNC authentication uses the first eight password bytes.
If Viewer cannot accept the password through the pipe, enter it in Viewer.
When vncconnect starts a desktop on its assigned host, the script answers the
department password prompt and gets a separate verification code if requested.
It waits for a code unused by either SSH login in this run. If the lab PC repeats
its password prompt after verification, the script retries that login once.
Startup continues while Pascal sends progress. After 90 seconds without output,
the script reports a timeout.
Leave this window open while using VNC. Press Ctrl+C to disconnect.
.PARAMETER LocalPort
Port on 127.0.0.1 for your VNC viewer. Defaults to 5905.
.PARAMETER Username
Department login. Defaults to mtjantzi.
.PARAMETER PasswordEntry
Optional path to the KeePassXC entry holding the department password in
otp.kdbx. The department password is then read from KeePassXC on each login.
.PARAMETER RefreshPasswords
Prompt again for the remembered passwords. Each replacement is saved after its
SSH or VNC login succeeds. If you use PasswordEntry, edit the department password
in KeePassXC.
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
