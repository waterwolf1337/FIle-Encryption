# Greg encrypted files

Greg is a desktop utility for wrapping an arbitrary file in an authenticated,
encrypted `.greg` container. It is not a document editor. When unlocked, Greg
creates a private temporary copy with its original filename and asks the operating
system to open that copy in the user's normal application.

## Security and file format

Format version 1 starts with the four bytes `GREG`. Its public binary header stores
the version, Argon2id cost parameters, random salt, random AES-GCM nonce, algorithm
identifiers, and ciphertext length. AES-256-GCM authenticates the full public header,
salt, nonce, and encrypted payload. The original filename, extension, optional
metadata, and file bytes are all inside that encrypted payload.
The exact version-1 layout is documented in [`docs/FORMAT.md`](docs/FORMAT.md).

Each newly created container uses a random 128-bit salt. Every encryption—including
Save and Lock—uses a fresh 96-bit nonce. The password is used only to derive a
256-bit key with Argon2id; no password hash is needed and neither password nor key is
written to persistent storage. Greg retains the derived key in process memory during
an unlocked session and clears its mutable key buffer when that session ends.

On Save and Lock, Greg stages ciphertext in the destination directory, flushes it,
and atomically replaces the old `.greg` only after staging succeeds. The temporary
plaintext is removed only after replacement succeeds. Cancel Changes leaves the old
container untouched.

## Installation

Python 3.12 or newer is required. Linux and Windows are supported; Linux is the
primary development platform and both platforms are included in the test matrix.

### Permanent per-user installation with `uv`

This is the recommended installation. It gives Greg its own managed environment and
places the `greg` command in `~/.local/bin`, so it works in every fresh terminal
without activating a virtual environment.

Run each command as a separate line. Do not append backslashes and do not include
Markdown formatting such as `**greg**`.

```bash
cd /home/gregor/storage/projects/FIle-Encryption
uv tool install .
greg --help
```

On a machine where `~/.local/bin` is not already on `PATH`, run this once and then
open a new terminal:

```bash
uv tool update-shell
```

On Linux, install the KDE/Dolphin MIME type and application entry after installing
Greg:

```bash
greg install-linux-integration
```

The desktop entry records the Python interpreter belonging to Greg's managed tool
environment. It therefore works without terminal activation. After this step you can
open `.greg` files from Dolphin as well as from a terminal.

### Windows installation

Open PowerShell. If `uv` is not installed, install it through WinGet:

```powershell
winget install --id=astral-sh.uv -e
```

Other supported installation methods are listed in the
[official `uv` installation guide](https://docs.astral.sh/uv/getting-started/installation/).

Open a new PowerShell window, change to the downloaded source directory, and install
Greg as an isolated user tool:

```powershell
cd C:\path\to\FIle-Encryption
uv tool install .
greg --help
greg install-windows-integration
```

The final command creates a current-user `.greg` association under
`HKEY_CURRENT_USER`; it does not require administrator rights. Windows may ask which
application to use the first time. If so, select **Greg encrypted file** and choose
to use it for `.greg` files. The association launches Greg through `pythonw.exe`, so
double-clicking a file does not leave a console window open.

### Updating an existing installation

After changing or downloading a newer copy of this source tree, reinstall it with:

```bash
cd /home/gregor/storage/projects/FIle-Encryption
uv tool install --force .
greg install-linux-integration
```

On Windows, run the equivalent commands in PowerShell and finish with:

```powershell
greg install-windows-integration
```

### Uninstalling

On Linux, remove the command and its managed Python environment with:

```bash
uv tool uninstall greg-encrypted-files
```

The KDE integration is stored separately. Remove it with:

```bash
rm -f ~/.local/share/applications/greg.desktop
rm -f ~/.local/share/mime/packages/greg.xml
update-mime-database ~/.local/share/mime
update-desktop-database ~/.local/share/applications
```

On Windows, remove the file association before removing the tool:

```powershell
greg uninstall-windows-integration
uv tool uninstall greg-encrypted-files
```

### Development installation

Contributors who want source edits to take effect immediately can instead use the
project virtual environment:

```bash
cd /home/gregor/storage/projects/FIle-Encryption
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
greg
```

This development installation only exposes `greg` while `.venv` is activated. Do not
use trailing backslashes between these commands; a backslash joins shell lines rather
than executing them separately.

## Usage

### Encrypt a file

1. Start Greg with `greg`.
2. Select **Encrypt File…**.
3. Select the original file, for example `finances.xlsx`.
4. Choose the destination, normally `finances.greg`.
5. Enter and confirm a non-empty password.
6. Keep or remove the original file yourself; Greg never deletes it automatically.

Losing the password means losing access to the encrypted data. Greg does not store a
password or a separate recovery hash.

### Open and edit a `.greg` file

1. Select **Open .greg…**, double-click the file in Dolphin/Explorer, or run
   `greg /path/to/document.greg`.
2. Enter the password.
3. Greg restores the original file in a private temporary directory and opens it in
   the operating system's default application.
4. Edit and save the file in that external application.
5. Preferably close the external application so all of its writes have finished.
6. Press **Save and Lock** in Greg. Greg encrypts the latest temporary contents,
   atomically replaces the `.greg`, and removes its temporary plaintext.

Press **Cancel Changes** to discard changes made to the temporary copy and leave the
existing `.greg` untouched.

### Command line

```bash
# Open the desktop application
greg

# Open a particular encrypted file
greg /path/to/document.greg

# Create finances.greg without deleting finances.xlsx
greg encrypt finances.xlsx

# Choose a different encrypted destination
greg encrypt finances.xlsx -o private/finances.greg

# Show only public format and cryptographic parameters
greg inspect finances.greg
```

`inspect` never asks for a password, reveals the encrypted filename, or writes
plaintext.

### Platform notes

Linux opens external files with `xdg-open`. Windows uses the normal Shell `open`
verb, stores its session registry beneath `%LOCALAPPDATA%\Greg`, and registers file
associations per user. Same-volume replacement through `os.replace` protects the old
container until the new ciphertext is staged on both platforms. Linux additionally
flushes the containing directory; Python's standard library does not expose the same
directory-flush operation on Windows.

Windows temporary files inherit the access control of the current user's `%TEMP%`
directory. Python's portable permission API cannot construct a stronger Windows ACL,
so Greg does not claim Unix-style `0600`/`0700` modes there. Administrator access and
other processes running as the same user remain outside the security boundary.

macOS has a launcher abstraction but does not yet have packaging, file association,
permission hardening, or end-to-end support.

Greg launches temporary files through `xdg-open` on Linux. It deliberately does not
wait for that process: desktop applications often accept an open request through an
existing process and let `xdg-open` exit immediately. The Greg control window remains
open until the user explicitly chooses **Save and Lock** or **Cancel Changes**.

## Temporary files and crash recovery

On Linux, unlocked directories and files are created with modes `0700` and `0600`.
On Windows, they are created inside the current user's randomly named temporary
directory and inherit that directory's ACL.
Directory names use a random `greg-session-` prefix and contain a Greg ownership
marker. A small registry stores only session IDs, directory paths, process IDs, and
creation times—never passwords, keys, filenames, or file contents. At startup, Greg
offers to delete verified abandoned session directories. It refuses to delete a
directory unless its location, prefix, and ownership marker all match.

Greg removes its temporary plaintext when an unlocked session ends normally. This is
not guaranteed secure deletion: SSD wear leveling, copy-on-write filesystems,
journals, snapshots, and backups make that promise impossible.

## Security model and limitations

`.greg` protects data while it is stored in encrypted form. While unlocked, an
ordinary plaintext file exists on disk because external applications require one.
Greg cannot protect against root/administrator access, malware, keyloggers, memory
inspection, another same-user process reading the unlocked file, swap, hibernation,
filesystem snapshots, backups, or storage-device behavior.

External applications may create their own autosave files, thumbnails, recent-file
entries, lock files, caches, or crash-recovery copies outside Greg's temporary
directory. Greg cannot reliably find or remove those artifacts. Save the document in
the external application and preferably close it before pressing Save and Lock.

## Tests

```bash
pytest
```

The suite covers cryptographic round trips, authentication failures, randomized
encryption, encrypted original metadata, save and cancel cycles, permissions and
cleanup ownership, stale-session discovery, and failure before atomic replacement.
