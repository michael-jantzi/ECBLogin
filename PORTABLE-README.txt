ECB Portable (Windows 10/11, x64)

Copy this ENTIRE folder to your USB stick. Double-click Connect-ECB.exe.
Unlock otp.kdbx with your existing KeePassXC vault password. When a department
or VNC password is not yet in the USB vault, enter it once; it is saved in the
encrypted vault only after that login succeeds. The vault unlock is requested
once per session and is never saved on the USB or in Windows Credential Manager.

Keep the console open while connected. Close Viewer or press Ctrl+C to end the
portable session. After the program closes, safely eject the USB stick.

Before a connection, you can open a terminal in this folder and run:
    .\Connect-ECB.exe --check
This checks files, SSH trust, and the KeePassXC runtime without unlocking the
vault or contacting the school. A successful check does not test the login.

Login progress identifies when the department password and verification code
are sent, without displaying either secret. If Pascal restarts login after
verification, the app retries once with the same password and waits for an
unused code. If that fails too, check the PC's date/time and retry. A password
rejected before verification stops immediately; use --refresh-passwords if
the encrypted USB copy has an outdated department password.

Settings live in data/settings.json. You can change username and local_port.
password_entry may name an existing KeePassXC entry for the department password;
leave it null to use the app's account-specific encrypted password entries.
Your OTP entry must be called ECB_Dept_AuthCode, as in the installed version.

To replace remembered department and VNC passwords, run:
    .\Connect-ECB.exe --refresh-passwords
Replacements are saved only after the corresponding login succeeds. If you use
password_entry, edit that department entry in KeePassXC instead. You can open
tools\KeePassXC\KeePassXC.exe to edit data\otp.kdbx. Close KeePassXC before
disconnecting the USB. App-created entries use ECB SSH or ECB VNC followed by
the username encoded as hexadecimal, so differently cased accounts stay separate.

data/known_hosts contains your trusted gateway public keys. A missing or changed
SSH key stops login. Verify any replacement fingerprint with the department
before updating this file. The app never accepts a new host key automatically.
An optional data/viewer.vnc must target your loopback port and cannot override
password delivery, logging, proxies, or the SSH tunnel destination. If you change
local_port, remove viewer.vnc or update its Host field to the same loopback port.

No Python, KeePassXC, or Viewer installation is needed on the target PC. It must
permit programs running from USB and have network access to the school. Portable
mode keeps its credentials and settings in this folder; Windows and third-party
programs can still keep normal execution traces. Use computers you trust with
the vault password. The encrypted vault copy can change independently of the
original vault on your laptop; keep a backup of the USB data folder.

An unconfigured build needs your encrypted otp.kdbx and verified known_hosts in
data before it can connect. Personal builds made with -ImportLocalData include
those files. Never publish or send this personal folder as a generic release.

For an update, build into a NEW folder and copy your existing USB data folder
into it, replacing the new build's data folder. Keep the old copy as a backup.
The builder refuses to overwrite an existing output folder.
