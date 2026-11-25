# ECB Login

ECB Login connects to the school's Pascal server, starts your assigned remote desktop, and opens it in RealVNC Viewer. It gets your changing verification codes from an encrypted KeePassXC vault so you do not have to copy them by hand.

This guide is for Windows users, including people who have not used PowerShell or Python before.

## Start here: which copy do you have?

| What you have | What to do |
| --- | --- |
| A prepared folder containing `Connect-ECB.exe`, `_internal`, `tools`, and `data` | Follow the [portable user guide](PORTABLE-README.txt). You can double-click the EXE; the computer needs no Python, KeePassXC, or Viewer installation. |
| A ZIP downloaded using GitHub's **Code > Download ZIP**, containing `.py` and `.ps1` files | Follow the source setup below. The GitHub source ZIP does not include the EXE, your vault, or bundled third-party programs. |
| A working source installation that you want to take on a USB stick | Complete [Build your own portable folder](#build-your-own-portable-folder). |

A prepared portable package is the easiest everyday option. Ask the project maintainer to prepare one for **your account** if you do not want to install or build anything. A package containing another person's verification codes will not work for your account just by changing its username.

## Know which password to use

| Prompt or term | What it means |
| --- | --- |
| Department username and password | Your department account used to sign in to `pascal.ee.ryerson.ca`. Use the department username with its correct capitalization. |
| KeePassXC vault password | The password that unlocks the encrypted file `otp.kdbx`. It can be different from your department password. |
| VNC desktop password | The password you set when configuring your school desktop through `vncconnect`. Ask the department if this has never been set up. |
| Verification code / OTP / TOTP | A short, changing code for the second sign-in step. This app reads it from KeePassXC automatically after setup. |

Passwords typed into the text window are hidden: you will not see letters, dots, or asterisks. Type the password and press **Enter** once. Your Windows password and your RealVNC website account password are not automatically the answers to these prompts.

## Set up the source version on your computer

Do this section once on the computer where you will run the PowerShell script or build the portable package. The portable package's destination computer does not need this setup.

### 1. Gather your account details and install the tools

You need a Windows computer with access to the school network, your department account, your VNC desktop password, and your own working verification-code setup. Use any VPN required by your department for that network.

Install these tools:

- **Python 3.10 or newer, 64-bit:** get it from [Python's official downloads](https://www.python.org/downloads/windows/). With the Python install manager, run its installer and follow the setup prompts; the `python` command can install a runtime on first use. With a traditional installer, select **Add python.exe to PATH** if offered. Close and reopen any PowerShell windows after installation. See the [official Windows instructions](https://docs.python.org/3/using/windows.html) if the commands are unavailable.
- **KeePassXC:** use the [official Windows download](https://keepassxc.org/download/#windows) and the standard installation location. The script needs `C:\Program Files\KeePassXC\keepassxc-cli.exe`.
- **A department-approved standalone RealVNC Viewer:** the script needs `C:\Program Files\RealVNC\VNC Viewer\vncviewer.exe`. Use the compatible Viewer supplied or approved by your department. RealVNC's newer Connect Viewer differs from Classic Viewer; ask the maintainer before substituting a different app or installation path. See [RealVNC's explanation of the Viewer versions](https://help.realvnc.com/hc/en-us/articles/35745908986653-Important-changes-to-RealVNC-Viewer-Information-and-FAQs).

If either required EXE is missing, finish installing the correct tool before continuing. On a managed computer, your administrator may need to install it for you.

### 2. Download and extract this project

1. Open the [ECBLogin repository](https://github.com/michael-jantzi/ECBLogin).
2. Click the green **Code** button, then **Download ZIP**.
3. Open your Downloads folder, right-click the downloaded ZIP, and select **Extract All**.
4. Open the extracted folder. If you see another folder inside it, open that too. Stop when you can see `Connect-ECB.ps1`, `ecb_login.py`, and `requirements.txt` together.
5. Move that whole folder somewhere convenient, such as Documents. Keep all the project files together. The instructions below call it the **project folder**.

Use the extracted folder, rather than running files from inside the ZIP. You do not need to install Git to use the download.

### 3. Open PowerShell in the project folder

1. In File Explorer, open the folder containing `Connect-ECB.ps1`.
2. Click File Explorer's address bar, type `powershell`, and press **Enter**.
3. A PowerShell window opens in that folder. Keep it open for the next steps.

Copy commands one line at a time, paste them into PowerShell, and press **Enter**. Wait for a command to finish before pasting the next one. Copy only the command, without the surrounding code-block marks or any `PS C:\...>` prompt.

Check Python:

```powershell
python --version
```

You should see `Python 3.10...` or a newer version. If Python is not recognized or opens the Microsoft Store without running it, finish the Python setup in step 1 and reopen PowerShell. If an existing Python launcher works with `py --version`, you can use `py` instead of `python` in the environment-creation command below.

### 4. Install the project's Python requirements

Run these commands separately in that same PowerShell window:

```powershell
python -m venv .venv
```

This creates a local folder named `.venv` containing the project's Python environment. It may finish without printing anything.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

This downloads the required libraries. Wait until the normal PowerShell prompt returns. A successful run has no final red error message; on repeat runs, `Requirement already satisfied` is normal. Keep `.venv` with the project. You do not need to activate it: the commands and script use it directly.

### 5. Put your verification-code vault in the expected place

The source version always reads this file:

```text
%LOCALAPPDATA%\ECB\otp.kdbx
```

`%LOCALAPPDATA%` is a shortcut to a folder for your Windows account, usually `C:\Users\YourName\AppData\Local`. Windows expands it when you use it in File Explorer's address bar.

If you already have a configured `otp.kdbx`:

1. Press **Windows key + E** to open File Explorer.
2. Type `%LOCALAPPDATA%` into its address bar and press **Enter**.
3. Create a folder named `ECB` if it is missing, then open it.
4. Copy your own configured vault into that folder and name it `otp.kdbx`. Keep your original as a backup. If a vault already exists there, back it up and confirm which copy you need before replacing anything.
5. Open this copy in KeePassXC and confirm you can unlock it with your vault password.

The vault must contain a **top-level entry named exactly `ECB_Dept_AuthCode`** with your department account's working TOTP setup. Keep it outside subgroups, because the script looks it up by that exact entry path.

If you need to create the vault:

1. In KeePassXC, choose **Create new database**, follow the wizard, and choose a vault password you can keep safely. This app supports a password-unlocked vault; key-file and hardware-key unlocks are not exposed by its login prompts.
2. Save it as `otp.kdbx` in the `ECB` folder above.
3. Select the database's top-level group and add an entry titled `ECB_Dept_AuthCode`.
4. Right-click that entry and choose **TOTP > Set up TOTP**. Enter the setup secret supplied through your department's authenticator enrollment process, then save. A current six-digit code is not the setup secret. If you only have codes on your phone and cannot obtain the secret, ask the department how to enroll this authenticator.
5. Save the database with **Ctrl+S**, then close KeePassXC before running the script.

KeePassXC's [getting started guide](https://keepassxc.org/docs/KeePassXC_GettingStarted) explains database creation and TOTP setup. The app reads codes from this vault; it does not enroll an authenticator with the school for you.

### 6. Verify Pascal's server identity once

The script needs a trusted SSH key for `pascal.ee.ryerson.ca`. An SSH key identifies the server you are connecting to.

1. Ask your department for the current official SSH fingerprint for Pascal.
2. In PowerShell, run the following command, replacing `your_department_username` with your own username:

   ```powershell
   ssh your_department_username@pascal.ee.ryerson.ca
   ```

3. If SSH asks whether to trust the host, compare its displayed fingerprint with the department's fingerprint. Type `yes` only when they match. This saves the trusted key in your Windows account's `.ssh\known_hosts` file.
4. Complete any department password and verification-code prompts. This one-time manual SSH login does not use the app's automatic code entry. You can view your current code in KeePassXC or your existing authenticator.
5. Once you reach the school's shell prompt, type `exit` and press **Enter** to return to your local PowerShell window.

If SSH reports that the host identification has changed, ask the department to verify the change before replacing the saved key. If `ssh` is unavailable, ask your administrator to enable Windows' OpenSSH Client.

### 7. Connect to your desktop

Back in PowerShell in the project folder, run:

```powershell
.\Connect-ECB.ps1 -Username your_department_username
```

Replace `your_department_username` with your own department username. **Always specify it for your account:** running without `-Username` uses the project's personal default, `mtjantzi`.

On your first successful run:

1. Enter your department password when asked.
2. Enter the KeePassXC password for `otp.kdbx` when asked. Both prompts hide what you type.
3. Wait while the program gets verification codes and starts the remote desktop. It can pause while waiting for an unused code.
4. Look for `VNC tunnel ready: 127.0.0.1:5905 -> ...`.
5. Enter your VNC desktop password when asked. RealVNC Viewer opens automatically. If automatic password delivery is unavailable, enter it directly in Viewer.
6. Keep the PowerShell window open while working. You can minimize it.

Successful source-version logins save passwords in **Windows Credential Manager for your Windows user on this computer**, including the vault unlock password. This differs from portable mode, which asks you to unlock the USB vault each session and saves department/VNC passwords inside that vault.

For later connections, open PowerShell in the project folder and run the same command. To finish, save your work, click the PowerShell window, and press **Ctrl+C**. In the source version, closing Viewer alone does not end the tunnel. Disconnecting does not guarantee that the remote desktop logs out.

If PowerShell says that running scripts is disabled, you can run the same login directly through the project's Python environment:

```powershell
.\.venv\Scripts\python.exe .\ecb_login.py --username your_department_username
```

This avoids changing your computer's execution policy. If your organization blocks the program itself, ask its administrator for help.

## Common source-version fixes

| What you see | What to try |
| --- | --- |
| A command or file is not recognized | Reopen PowerShell from the correct project folder. Include the leading `.\` where shown. Confirm the ZIP was extracted. |
| A message asking you to set up `.venv`, or a missing Python module | Repeat step 4 from the project folder. Use `.\.venv\Scripts\python.exe` for installation so the libraries go into this project's environment. |
| KeePassXC CLI or the OTP database was not found | Check the exact KeePassXC installation path in step 1 and the vault location in step 5. |
| A vault password or entry could not be read | Open the expected vault in KeePassXC. Confirm its password and the exact top-level entry name `ECB_Dept_AuthCode`. |
| Department or VNC password changed | Run `.\Connect-ECB.ps1 -Username your_department_username -RefreshPasswords`. Enter the current department, vault, and VNC passwords when asked; confirmed replacements are saved. This updates stored copies, not the account passwords themselves. |
| Verification codes are rejected | Check Windows **Settings > Time & language > Date & time**, enable automatic time, and use **Sync now** if available. Confirm the vault contains your account's TOTP secret. |
| Port `5905` is already in use | Close an older ECB session, or run `.\Connect-ECB.ps1 -Username your_department_username -LocalPort 5910`. |
| Viewer does not open automatically | Confirm the required Viewer path in step 1. While the tunnel is ready, open your compatible Viewer manually and connect to `127.0.0.1:5905`, or `127.0.0.1::5910` if you chose port 5910. |
| Cannot verify the SSH key | Repeat the identity verification in step 6 with department help. |
| Connection or VNC startup times out | Check internet/VPN access and try again. The program stops after 90 seconds without output from Pascal. Contact the department if it keeps happening. |

For help, share the error text and which step failed. Keep passwords, the authenticator setup secret, and your personal vault private.

## Build your own portable folder

Build on a **Windows x64 computer using 64-bit Python** after the source setup works. The builder copies your installed KeePassXC and authorized RealVNC Viewer, bundles Python and supporting libraries, and creates a folder you can carry on USB.

### 1. Install the build tools

Open PowerShell in the project folder and run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
```

### 2. Build a package for your own account

Run this command, replacing `your_department_username`:

```powershell
.\Build-Portable.ps1 -Username your_department_username -ImportLocalData
```

`-ImportLocalData` copies your encrypted vault from `%LOCALAPPDATA%\ECB\otp.kdbx`, exports your verified Pascal SSH trust, and imports remembered department/VNC passwords into the **copied** vault when available. It preserves your original vault and Windows credentials. It does not save the vault unlock password in the portable package.

Without `-ImportLocalData`, the build lacks the personal vault and server-trust file and cannot connect until configured. For a ready-to-use personal USB folder, include the switch as shown. If no saved passwords are available to import, you can enter them on the first portable login.

If PowerShell blocks this script, use its Python equivalent:

```powershell
.\.venv\Scripts\python.exe .\build_portable.py --username your_department_username --import-local-data
```

Wait for `Portable folder ready:` and a folder path. Builds can take several minutes and print many progress lines. The normal output is:

```text
dist\ECB-Portable\
    Connect-ECB.exe
    _internal\
    tools\
    data\
    README.txt
    THIRD-PARTY.txt
    manifest.json
```

The builder refuses to overwrite an existing output folder. For another build, choose a new name:

```powershell
.\Build-Portable.ps1 -Username your_department_username -ImportLocalData -OutputPath '.\dist\ECB-Portable-New'
```

If a build reports a missing Microsoft runtime DLL, ask the maintainer to supply the required x64 runtimes. The Python builder's `--runtime-dir` option accepts their folder; `--help` also lists options for nonstandard KeePassXC and Viewer input locations.

### 3. Check it, copy it, and connect

From the project folder, check the default output:

```powershell
.\dist\ECB-Portable\Connect-ECB.exe --check
```

Adjust `ECB-Portable` if you used a different output name. This checks files, server trust, and KeePassXC startup without unlocking the vault or contacting the school. It does not test login or start Viewer.

Copy the **entire output folder** to the USB stick, then follow its `README.txt` (the [portable user guide](PORTABLE-README.txt)) for first login, password changes, troubleshooting, backups, and updates. Keep this personal package private; it contains your encrypted verification-code and password vault.

The portable `README.txt` is copied from `PORTABLE-README.txt` when you build. Existing packages keep their previous guide until you replace that text file or make a new build. Third-party programs remain subject to their own terms; see [THIRD-PARTY.txt](THIRD-PARTY.txt).

## Optional: read the department password from an existing vault entry

If you already keep the department password in an entry such as `Department/SSH`, you can use it instead of the app's remembered department password:

```powershell
.\Connect-ECB.ps1 -Username your_department_username -PasswordEntry 'Department/SSH'
```

Replace the example entry path with its actual group/title path in `otp.kdbx`. For portable mode, set `password_entry` in `data/settings.json` to that path instead of `null`. Update that entry in KeePassXC when the department password changes; the refresh option does not replace a department password supplied through `PasswordEntry`.
