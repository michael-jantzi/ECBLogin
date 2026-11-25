"""Build a personal Windows x64 USB folder. Never overwrite an existing folder."""

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import asyncssh

from ecb_credentials import read_password
from ecb_login import GATEWAY, LoginClient
from ecb_portable import DEFAULT_SETTINGS, PortableSession, PortableVault
from ecb_viewer_profile import find_viewer_profile


ROOT = Path(__file__).resolve().parent
RUNTIME_DLLS = (
    "msvcp140.dll", "msvcp140_1.dll", "msvcp140_2.dll", "msvcp140_atomic_wait.dll",
    "msvcp140_codecvt_ids.dll", "vcruntime140.dll", "vcruntime140_1.dll", "concrt140.dll",
)


def export_trust(source, destination):
    """Export only the gateway's existing trust, including revocations."""
    trusted, ca, revoked, *_ = asyncssh.read_known_hosts(str(source)).match(GATEWAY, "", 22)
    if not trusted and not ca:
        raise RuntimeError(f"No trusted key for {GATEWAY} in {source}. Verify it with the department first.")
    lines = ["# Gateway trust copied from your existing SSH known_hosts.\n"]
    for prefix, keys in (("", trusted), ("@cert_authority ", ca), ("@revoked ", revoked)):
        for key in keys:
            public_key = key.export_public_key("openssh").decode("ascii").strip()
            lines.append(f"{prefix}{GATEWAY} {public_key}\n")
    destination.write_text("".join(lines), encoding="utf-8")


def copy_viewer_profile(destination, port):
    profile = find_viewer_profile(port)
    if profile is None:
        return
    import codecs
    data = profile.read_bytes()
    encoding = "utf-16" if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)) else "utf-8-sig"
    # Viewer must use the private pipe, independently of this PC's credential store.
    lines = [line for line in data.decode(encoding).splitlines()
             if line.partition("=")[0].strip().casefold() != "credentialstore"]
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8")


def import_personal_data(bundle, username, vault_source, known_hosts_source):
    data = bundle / "data"
    if not vault_source.is_file():
        raise FileNotFoundError(f"OTP vault is missing: {vault_source}")
    shutil.copy2(vault_source, data / "otp.kdbx")
    export_trust(known_hosts_source, data / "known_hosts")
    copy_viewer_profile(data / "viewer.vnc", DEFAULT_SETTINGS["local_port"])
    master = read_password(f"ECB Login Script/KeePassXC/{vault_source.resolve()}")
    if master is None:
        print("No remembered vault unlock found. Enter department and VNC passwords on the first portable login.")
        return
    vault = PortableVault(bundle / "tools" / "KeePassXC" / "keepassxc-cli.exe", data / "otp.kdbx", lambda _: master)
    try:
        vault.unlock()
        account = LoginClient(username, None)
        count = 0
        for service in ("SSH", "VNC"):
            target = account.account_target(service)
            secret = read_password(target)
            if secret is not None:
                vault.save_password(target, username, secret)
                count += 1
            secret = None
        print(f"Copied the encrypted vault and imported {count} remembered login passwords into the copy.")
    finally:
        vault.clear()
        master = None


def copy_runtimes(source, destination):
    for name in RUNTIME_DLLS:
        path = source / name
        if path.is_file():
            shutil.copy2(path, destination / name)
    for name in ("msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        if not (destination / name).is_file():
            raise FileNotFoundError(f"Missing Microsoft runtime {name}. Supply --runtime-dir with the x64 runtime DLLs.")


def check_pe_dependencies(bundle):
    """Ensure non-Windows imports are local, rather than hidden installed dependencies."""
    import pefile

    system = Path(os.environ["WINDIR"]) / "System32"
    files = [path for path in bundle.rglob("*") if path.suffix.lower() in {".exe", ".dll", ".pyd"}]
    dll_directories = {bundle / "_internal", bundle / "_internal" / "pywin32_system32"}
    for path in files:
        pe = pefile.PE(str(path), fast_load=True)
        try:
            if pe.FILE_HEADER.Machine != 0x8664:
                raise RuntimeError(f"Expected an x64 binary: {path.name}")
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            for item in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                name = item.dll.decode("ascii")
                if name.lower().startswith(("api-ms-", "ext-ms-")):
                    continue
                search = {path.parent} | dll_directories
                if path.is_relative_to(bundle / "tools" / "KeePassXC"):
                    search = {path.parent, bundle / "tools" / "KeePassXC"}
                elif path.is_relative_to(bundle / "tools" / "RealVNC"):
                    search = {bundle / "tools" / "RealVNC"}
                local = any((directory / name).is_file() for directory in search)
                # Microsoft C++ runtimes are not guaranteed to be installed on the target.
                runtime = name.lower().startswith(("msvcp140", "vcruntime140", "concrt140"))
                if not local and (runtime or not (system / name).is_file()):
                    raise RuntimeError(f"Unbundled dependency: {path.name} needs {name}")
        finally:
            pe.close()


def write_manifest(bundle):
    # Personal data is deliberately excluded from the manifest.
    manifest = {"architecture": "Windows x64", "packages": {}, "files": {}}
    for package in ("asyncssh", "cryptography", "pywin32", "pyinstaller", "pyinstaller-hooks-contrib"):
        manifest["packages"][package] = importlib.metadata.version(package)
    for directory in (bundle / "tools", bundle / "_internal"):
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                manifest["files"][path.relative_to(bundle).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest["files"]["Connect-ECB.exe"] = hashlib.sha256((bundle / "Connect-ECB.exe").read_bytes()).hexdigest()
    (bundle / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


def build(args):
    if sys.platform != "win32" or struct.calcsize("P") != 8 or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise RuntimeError("Build this package with x64 Python on Windows.")
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"Output already exists; choose a new folder to preserve its data: {output}")
    for path in (args.keepassxc_dir / "keepassxc-cli.exe", args.viewer):
        if not path.is_file():
            raise FileNotFoundError(f"Required build input is missing: {path}")
    build_root = ROOT / "build"
    build_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="portable-", dir=build_root) as temporary:
        stage = Path(temporary)
        subprocess.run([
            sys.executable, "-m", "PyInstaller", "--noconfirm", "--onedir", "--console",
            "--name", "Connect-ECB", "--distpath", str(stage / "dist"),
            "--workpath", str(stage / "work"), "--specpath", str(stage),
            "--collect-all", "asyncssh", "--hidden-import", "win32timezone",
            str(ROOT / "ecb_portable_launcher.py"),
        ], cwd=ROOT, check=True)
        bundle = stage / "dist" / "Connect-ECB"
        tools = bundle / "tools"
        keepass = tools / "KeePassXC"
        shutil.copytree(args.keepassxc_dir, keepass,
                        ignore=shutil.ignore_patterns("vc_redist*.exe", "*.kdbx", "*.keyx", "*.key"))
        copy_runtimes(args.runtime_dir, keepass)
        (tools / "RealVNC").mkdir(parents=True)
        shutil.copy2(args.viewer, tools / "RealVNC" / "vncviewer.exe")
        # Keeps KeePassXC GUI settings next to the executable if the user opens it.
        (keepass / "keepassxc.ini").write_text("", encoding="utf-8")
        data = bundle / "data"
        data.mkdir()
        settings = dict(DEFAULT_SETTINGS, username=args.username)
        (data / "settings.json").write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
        shutil.copy2(ROOT / "PORTABLE-README.txt", bundle / "README.txt")
        shutil.copy2(ROOT / "THIRD-PARTY.txt", bundle / "THIRD-PARTY.txt")
        if args.import_local_data:
            import_personal_data(bundle, args.username, args.vault, args.known_hosts)
            session = PortableSession(bundle, lambda _: "")
            session.check(GATEWAY)
        check_pe_dependencies(bundle)
        write_manifest(bundle)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(bundle, output)
    print(f"Portable folder ready: {output}")


def prepare_existing(args):
    """Populate an already-built, unconfigured personal folder without rebuilding."""
    output = args.output.resolve()
    session = PortableSession(output, lambda _: "")
    for path in (output / "Connect-ECB.exe", session.cli, session.viewer, session.data / "settings.json"):
        if not path.is_file():
            raise FileNotFoundError(f"Build the portable folder first. Missing: {path}")
    for name in ("otp.kdbx", "known_hosts", "viewer.vnc"):
        if (session.data / name).exists():
            raise FileExistsError(f"Personal data already exists; it will not be overwritten: {session.data / name}")
    import_personal_data(output, session.settings["username"], args.vault, args.known_hosts)
    session.check(GATEWAY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "ECB-Portable")
    parser.add_argument("--keepassxc-dir", type=Path, default=program_files / "KeePassXC")
    parser.add_argument("--viewer", type=Path, default=program_files / "RealVNC" / "VNC Viewer" / "vncviewer.exe")
    parser.add_argument("--runtime-dir", type=Path, default=Path(os.environ.get("WINDIR", "C:/Windows")) / "System32")
    parser.add_argument("--username", default=DEFAULT_SETTINGS["username"])
    parser.add_argument("--import-local-data", action="store_true", help="copy local vault/trust and import remembered passwords")
    parser.add_argument("--prepare-existing", action="store_true", help="populate a built folder; requires --import-local-data")
    parser.add_argument("--vault", type=Path, default=Path(os.environ.get("LOCALAPPDATA", ".")) / "ECB" / "otp.kdbx")
    parser.add_argument("--known-hosts", type=Path, default=Path.home() / ".ssh" / "known_hosts")
    args = parser.parse_args()
    if args.prepare_existing and not args.import_local_data:
        parser.error("--prepare-existing requires --import-local-data")
    try:
        if args.prepare_existing:
            prepare_existing(args)
        else:
            build(args)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Portable build failed: {exc}")


if __name__ == "__main__":
    main()
