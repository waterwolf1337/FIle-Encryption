from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from greg.format.greg_file import encrypt_new, inspect_header
from greg.format.payload import GregPayload
from greg.storage import atomic_write


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments in (["-h"], ["--help"]):
        print(
            "usage: greg [FILE.greg]\n"
            "       greg open FILE.greg\n"
            "       greg encrypt FILE [-o OUTPUT.greg]\n"
            "       greg inspect FILE.greg\n"
            "       greg install-linux-integration\n"
            "       greg install-windows-integration\n"
            "       greg uninstall-windows-integration"
        )
        return 0
    if arguments and arguments[0] == "encrypt":
        return _encrypt_command(arguments[1:])
    if arguments and arguments[0] == "inspect":
        return _inspect_command(arguments[1:])
    if arguments and arguments[0] == "install-linux-integration":
        return _install_linux_integration(arguments[1:])
    if arguments and arguments[0] == "install-windows-integration":
        return _install_windows_integration(arguments[1:])
    if arguments and arguments[0] == "uninstall-windows-integration":
        return _uninstall_windows_integration(arguments[1:])
    if arguments and arguments[0] == "open":
        arguments.pop(0)
    if len(arguments) > 1:
        print("Run 'greg --help' for usage.", file=sys.stderr)
        return 2
    from greg.ui.application import run_gui

    return run_gui(Path(arguments[0]).resolve() if arguments else None)


def _encrypt_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="greg encrypt")
    parser.add_argument("file", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    options = parser.parse_args(argv)
    source = options.file.resolve(strict=True)
    destination = options.output.resolve() if options.output else source.with_suffix(".greg")
    if destination == source:
        parser.error("output must not overwrite the source file")
    password = getpass.getpass("Password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if not password or password != confirmation:
        print("Passwords are empty or do not match.", file=sys.stderr)
        return 2
    payload = GregPayload(source.name, source.read_bytes())
    atomic_write(destination, encrypt_new(payload, password))
    print(destination)
    return 0


def _inspect_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="greg inspect")
    parser.add_argument("file", type=Path)
    options = parser.parse_args(argv)
    header = inspect_header(options.file.read_bytes())
    print(
        json.dumps(
            {
                "version": header.version,
                "kdf": "Argon2id",
                "cipher": "AES-256-GCM",
                "argon2": {
                    "time_cost": header.parameters.time_cost,
                    "memory_cost_kib": header.parameters.memory_cost_kib,
                    "parallelism": header.parameters.parallelism,
                },
                "salt_length": header.salt_length,
                "nonce_length": header.nonce_length,
                "ciphertext_length": header.ciphertext_length,
            },
            indent=2,
        )
    )
    return 0


def _install_linux_integration(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="greg install-linux-integration")
    parser.parse_args(argv)
    if not sys.platform.startswith("linux"):
        parser.error("this command is only supported on Linux")
    from greg.platforms.linux import install_file_association

    desktop, mime = install_file_association()
    print(f"Installed {desktop}\nInstalled {mime}")
    return 0


def _install_windows_integration(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="greg install-windows-integration")
    parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("this command is only supported on Windows")
    from greg.platforms.windows import install_file_association

    install_file_association()
    print("Registered .greg for the current Windows user.")
    return 0


def _uninstall_windows_integration(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="greg uninstall-windows-integration")
    parser.parse_args(argv)
    if sys.platform != "win32":
        parser.error("this command is only supported on Windows")
    from greg.platforms.windows import uninstall_file_association

    uninstall_file_association()
    print("Removed Greg's current-user Windows file association.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
