"""Find a saved RealVNC Viewer connection for the local SSH tunnel."""

import codecs
import os
import re
from pathlib import Path


# Per-connection settings can override the authentication and logging options on Viewer's command line.
LAUNCH_SETTINGS = {
    "passwordfile", "passwd", "password", "encryptedpassword",
    "log", "logdir", "logfile", "logtoaddressbook", "useaddressbook",
}
ALTERNATE_TARGET_SETTINGS = {
    "config", "configfile", "vncconfigfile", "include", "uri", "url",
    "via", "gateway", "sshgateway", "server", "port", "rfbport",
}


def _profile_port(profile: Path) -> int | None:
    data = profile.read_bytes()
    encoding = "utf-16" if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    settings = data.decode(encoding)
    if "\0" in settings:
        return None
    hosts = []
    for line in settings.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";", "[")):
            continue
        name, separator, value = line.partition("=")
        name = name.strip().lstrip("-").lower()
        value = value.strip().lower()
        if not separator or name in LAUNCH_SETTINGS or (name in ALTERNATE_TARGET_SETTINGS and value):
            return None
        if name.startswith("proxy") and value:
            if not (name == "proxytcprfb" and value in {"0", "false"}):
                return None
        if name == "host":
            hosts.append(value)
    if len(hosts) != 1:
        return None
    endpoint = hosts[0]
    if endpoint in {"127.0.0.1", "localhost"}:
        return 5900
    # RealVNC accepts :0 through :99 as display numbers and ::N as an explicit TCP port.
    match = re.fullmatch(r"(127\.0\.0\.1|localhost)?(:{1,2})([0-9]{1,5})", endpoint)
    if not match:
        return None
    host, separator, number = match.groups()
    port = int(number)
    if separator == ":" and port < 100:
        return 5900 + port
    return port if host else None


def find_viewer_profile(local_port: int) -> Path | None:
    """Return the unique saved profile addressing this loopback TCP port."""
    app_data = os.environ.get("APPDATA")
    if not app_data or not 1 <= local_port <= 65535:
        return None
    match = None
    try:
        for profile in (Path(app_data) / "RealVNC" / "ViewerStore").glob("*.vnc"):
            try:
                if _profile_port(profile) == local_port:
                    if match is not None:
                        return None
                    match = profile
            except (OSError, UnicodeError):
                continue
    except OSError:
        return None
    return match
