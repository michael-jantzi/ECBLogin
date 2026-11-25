ECB PORTABLE - STEP-BY-STEP USER GUIDE
Windows 10 or 11, 64-bit (x64)

This program opens your school's remote desktop in RealVNC Viewer. It signs
in through the school's Pascal server and gets verification codes from your
encrypted KeePassXC password file, called otp.kdbx.

If someone has already prepared your USB folder, start at section 1. You do
not need to install Python, KeePassXC, or RealVNC Viewer on the computer you
connect from. The required programs are included in the prepared folder.

If you downloaded the GitHub source files and cannot find Connect-ECB.exe,
you do not have a built portable package yet. Follow README.md in the source
folder, or ask the person maintaining this project to prepare your package.


1. WHAT YOU NEED BEFORE STARTING
===============================

Have these ready:

- A Windows 10/11 x64 computer with internet access to the school. The computer
  must allow programs to run from a USB stick.
- The complete portable folder prepared for YOUR department account.
- Your department username and password.
- The password that unlocks your KeePassXC vault (otp.kdbx).
- Your VNC desktop password, if it has not already been saved in the USB vault.
  This is the password you set when configuring VNC through vncconnect.

There are three different passwords you may be asked for:

  Vault password       Unlocks otp.kdbx so the program can read your codes.
  Department password  Signs in to your school department account on Pascal.
  VNC desktop password Opens your remote desktop in RealVNC Viewer.

These passwords may be different. Your Windows sign-in password or a RealVNC
website account password is not automatically the password for these prompts.
Ask your department for help if VNC has never been set up for your account.


2. COPY THE COMPLETE FOLDER TO YOUR USB STICK
===========================================

1. Plug in your USB stick and open File Explorer (Windows key + E).
2. Find the portable folder you were given. A locally built copy is normally
   in dist\ECB-Portable inside the project folder.
3. Right-click the entire portable folder and choose Copy.
4. In File Explorer, open This PC, then open your USB drive.
5. Right-click an empty area and choose Paste. Wait for copying to finish.
   The copied folder can be named ECB-Portable, ECBLogin, or another name.
6. Open the copied folder on the USB. You should see at least:

       Connect-ECB.exe       The program you double-click to connect.
       _internal\           Supporting files; keep this folder with the EXE.
       tools\               The included KeePassXC and RealVNC programs.
       data\                Your settings, encrypted vault, and server trust.
       README.txt           This guide.

   Inside data, a prepared copy needs these files:

       settings.json        Your username and connection settings.
       otp.kdbx             Your encrypted vault and verification-code entry.
       known_hosts          The school's verified SSH server keys.

   There may also be a viewer.vnc file for saved display preferences.

Copying only Connect-ECB.exe will not work. If you received a ZIP file,
right-click it, choose Extract All, and use the extracted folder first.
If extensions are hidden, the EXE may appear as Connect-ECB with its Type
shown as Application.

Missing otp.kdbx or known_hosts? Ask for a configured package for your own
account. The program does not create your school account, enroll your
verification codes, or accept an unverified school server automatically.


3. CHECK YOUR USERNAME ONCE
==========================

1. Open the data folder inside your USB program folder.
2. Right-click settings.json and choose Open with, then Notepad.
3. Find the username line. Replace the value inside the quotation marks with
   your department username. Use the same capitalization as your account.
   The project's default, mtjantzi, must be changed for another user.
4. For a normal setup, the complete file looks like this:

       {
         "username": "your_department_username",
         "local_port": 5905,
         "password_entry": null
       }

   Replace your_department_username with your actual username. Keep the
   quotation marks, commas, and braces as shown. Keep null without quotes.
5. Press Ctrl+S to save, then close Notepad. Keep the name settings.json;
   do not save a second file named settings.json.txt.

Leave local_port and password_entry as shown unless you need the changes in
sections 7 or 8. Passwords belong in the encrypted vault, not settings.json.
Changing the username does not change whose verification codes are in the
vault. Your otp.kdbx must already contain YOUR account's codes.


4. CONNECT FOR THE FIRST TIME
============================

1. Open the USB program folder and double-click Connect-ECB.exe.
2. A text window opens. At this prompt:

       Unlock the USB vault (otp.kdbx):

   Type your KeePassXC vault password and press Enter. Nothing appears while
   you type, not even dots or asterisks. This is normal.
3. If asked for "Department password for ...", type your department password
   and press Enter. This prompt is skipped when the USB vault already has it.
4. Wait while the program signs in and starts the desktop. It reads the
   changing verification codes automatically; you normally do not type one.
   A message about waiting for a fresh code or retrying once can be normal.
   Leave the window open while progress continues.
5. Look for "VNC tunnel ready: 127.0.0.1:5905 -> ...". This means the local
   connection to your school desktop is ready. RealVNC Viewer opens next.
6. If asked for "VNC desktop password for ...", enter the VNC password you
   previously set with vncconnect, then press Enter. If automatic password
   delivery is unavailable, enter that password in the Viewer window instead.
7. When your school desktop appears, you are connected. Keep the text window
   open for the whole session. You can minimize it while you work.

On later connections, double-click the EXE and unlock the vault again.
Successful department and VNC passwords are remembered in the encrypted USB
vault. The vault unlock password is requested each session and is never saved
by the portable app on the USB or in Windows Credential Manager. A password
typed manually into Viewer may need to be entered again next time.


5. FINISH AND SAFELY REMOVE THE USB
==================================

1. Save your work in the remote desktop.
2. Close the RealVNC session window, or click the text window and press Ctrl+C
   (hold Ctrl and tap C). Either action ends the portable connection.
3. If the text window says "Press Enter to close this window ...", press Enter.
4. Close portable KeePassXC too, if you opened it to edit the vault.
5. Use Windows' Safely Remove Hardware / Eject option for the USB drive and
   wait for confirmation before unplugging it.

Disconnecting closes your connection. Save your work first; it does not promise
to log you out of the school desktop or stop programs running there.


6. HOW TO OPEN A COMMAND WINDOW IN THE RIGHT FOLDER
=================================================

The commands below are for troubleshooting or changing saved passwords.
You do not need them for normal double-click use.

1. Open the USB folder that contains Connect-ECB.exe in File Explorer.
2. Click the address bar at the top, where the folder's location appears.
3. Type powershell and press Enter. A PowerShell window opens in that folder.
4. Copy ONE command line from this guide, paste it into PowerShell, and press
   Enter. Wait for it to finish before running another command.

The .\ at the beginning means "run the program in this folder". Include it.
Do not type a prompt such as PS E:\ECBLogin>; only type the command itself.

Check the portable files without signing in:

    .\Connect-ECB.exe --check

A successful check prints "Portable files and SSH trust are ready" and
"KeePassXC starts successfully". This checks the required files, server trust,
and KeePassXC startup. It does not unlock the vault, test your passwords,
contact the school, or prove the remote desktop will connect.

Test the school gateway login without opening a desktop:

    .\Connect-ECB.exe --check-login

This displays the computer's current UTC time, asks you to unlock the vault,
and signs in to Pascal. Success prints "Gateway login verified. No desktop
was started." It does not test the VNC desktop password.


7. CHANGE A SAVED PASSWORD
=========================

If your department or VNC password changed, open PowerShell as described in
section 6 and run:

    .\Connect-ECB.exe --refresh-passwords

Unlock the vault and enter the current department and VNC passwords when
asked, even if only one changed. Each replacement is saved only after its
corresponding login succeeds. The USB must be writable to save changes.
This command updates the saved copies; it does not change your school or
VNC account password itself.

If password_entry names an existing department-password entry instead of
null, edit that entry in KeePassXC instead:

1. Open tools\KeePassXC and double-click KeePassXC.exe.
2. Choose Open existing database and select data\otp.kdbx from the USB program
   folder. Enter its vault password.
3. Open the entry named by password_entry, update its Password field, and save
   the database with Ctrl+S. Close KeePassXC before reconnecting.

To change the vault unlock password, use KeePassXC's database security settings
and save the database. Use the new password next time you start the app.
The app-created entries begin with ECB SSH or ECB VNC followed by the username
encoded as hexadecimal (letters and numbers). Leave those names unchanged.


8. COMMON PROBLEMS AND WHAT TO DO
===============================

"Could not unlock the USB vault"
  Enter the password for otp.kdbx. Check Caps Lock and your keyboard layout.
  If you forgot it, use your own backup/recovery arrangements; the app cannot
  recover the vault password. Changing the department password will not help.

"Required portable file is missing" / the EXE does not start
  Check that you copied the ENTIRE extracted folder, including _internal,
  tools, and data. Run --check. Ask the maintainer for a complete package if
  needed. If the computer blocks USB programs, ask its administrator for help.

"Connect-ECB.exe is not recognized"
  Reopen PowerShell from the folder containing the EXE (section 6), then run
  the command with the leading .\ exactly as shown.

"data/settings.json must contain valid JSON"
  Reopen settings.json in Notepad and compare it with section 3. Look for a
  missing quote, comma, or brace, or an extra comma after the final setting.

Department password rejected / "Login failed"
  Check the username in settings.json, including capitalization. If the saved
  department password changed, run --refresh-passwords (section 7). If it is
  still rejected, confirm the account works with your department.

Verification code rejected / Pascal restarts login after verification
  Check Windows Settings > Time & language > Date & time. Enable automatic
  time and use Sync now if available, then reconnect. The app retries once
  with an unused code. If it keeps failing, ask someone to check that the
  vault has your account's TOTP setup in an entry named ECB_Dept_AuthCode.
  A fresh code can require a short wait; do not repeatedly start new copies.

"Could not listen on 127.0.0.1:5905"
  Another program or another copy may already use that local connection port.
  Close an old ECB session first. If you need a different port, close the app,
  change local_port in settings.json to 5910, and save. If data\viewer.vnc
  exists, rename it to viewer.vnc.backup so it no longer selects the old port.
  Then start the app again. A port is a numbered connection on this computer;
  you do not need to change the school's server settings.

"data/viewer.vnc must describe this local port ..."
  Close the app and rename data\viewer.vnc to viewer.vnc.backup, then retry.
  The app can connect without that optional display-preference file.

"Could not verify the SSH key" / known_hosts error
  Ask the department to verify the fingerprint (the server's identity) and
  help update data\known_hosts. Keep server verification enabled. A changed
  key needs confirmation before a replacement is trusted.

"KeePassXC could not read 'ECB_Dept_AuthCode'"
  Open your USB data\otp.kdbx in the included KeePassXC. Confirm that the
  top-level entry is named exactly ECB_Dept_AuthCode and has your working
  time-based verification-code setup. Ask the maintainer if it is missing.

Viewer rejects the password / "VNC login was not confirmed"
  Use the VNC desktop password set through vncconnect. Run --refresh-passwords
  to replace the app's saved copy. Classic VNC authentication uses only the
  first eight password bytes. Ask the department if you need a VNC reset.

Timeout / cannot reach Pascal / connection closes unexpectedly
  Check internet access and any school-required VPN, then retry. Startup
  times out after 90 seconds without output from Pascal. If it repeats, use
  --check-login to narrow down the problem and contact the department with
  the error message. Do not send your passwords or vault file with it.


9. BACK UP YOUR DATA AND UPDATE THE PROGRAM
=========================================

The USB vault can change independently of the original vault on your laptop.
Passwords changed on one copy do not automatically update the other.

To back up:
1. Close the ECB program and portable KeePassXC.
2. Copy the entire data folder to a safe backup location you control.
3. Keep track of which copy is newest. Keep its vault password available
   through your own password-recovery arrangements.

To move to a newer portable build:
1. Keep the old working program folder and back up its data folder first.
2. Put the new build in a DIFFERENT folder, rather than pasting it over the old
   working copy. The builder also refuses an existing output folder.
3. In the new build, rename its data folder to data-from-new-build.
4. Copy your old working data folder into the new build's folder. It must sit
   beside Connect-ECB.exe and still be named data.
5. Run --check from the new folder, then try a normal connection.
6. Keep the old working folder until you have confirmed the update works.

Use computers you trust with your vault password. Portable mode keeps its
credentials and settings in this folder, but Windows and third-party programs
can still keep normal execution traces. Keep your personal portable folder
private; it contains your encrypted verification-code and password database.

For source setup and building, see README.md in the GitHub project. For the
included software's terms and notices, see THIRD-PARTY.txt in this folder.
