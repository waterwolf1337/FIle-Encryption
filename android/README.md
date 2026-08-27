# Greg for Android

Greg for Android encrypts, opens, edits, and re-encrypts the same version-1
`.greg` files as the Linux and Windows desktop application. It is a native Kotlin
application for Android 8.0 (API 26) and newer.

## Install a development APK

The repository includes the Gradle wrapper. Install Android Studio or an Android
SDK containing platform 36 and build-tools 36, enable USB debugging on the phone,
then connect it by USB.

```bash
cd android
export ANDROID_HOME="$HOME/Android/Sdk"
./gradlew testDebugUnitTest assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

If the phone asks whether to allow USB debugging or USB installation, approve the
prompt and rerun the final command. The installed application is named **Greg**.
This is currently a development APK; there is no Play Store release or stable
signed release package yet.

To run the storage/session tests on a connected phone or emulator:

```bash
./gradlew connectedDebugAndroidTest
```

## Use it

### Encrypt a file

1. Open Greg and tap **Encrypt file…**.
2. Select any document using Android's system file picker.
3. Enter and confirm a password.
4. Choose where to create the suggested `.greg` file.

Greg does not delete the unencrypted original. Remove it yourself only after you
have verified that the `.greg` file opens with the password.

### Open and edit a `.greg` file

1. Tap **Open .greg…** and select the file. You can also tap a `.greg` file in a
   file manager and choose Greg when Android offers compatible applications.
2. Enter the password.
3. Greg writes the decrypted file to its private app storage and grants a temporary
   content URI to an installed editor for that file type.
4. Edit and save in the external application, then return to Greg.
5. Tap **Save and lock** to create fresh ciphertext and remove Greg's temporary
   plaintext. Tap **Cancel changes** to remove the plaintext without changing the
   existing `.greg` file.

If Android kills Greg while a document is unlocked, the next launch offers to
recover or remove the abandoned session. Recovery asks for the password again when
you save because encryption keys are never persisted.

## Storage and security behavior

The implementation uses Android's Storage Access Framework, so files can reside in
Downloads or in a document provider such as a cloud drive without broad storage
permission. Temporary plaintext stays under the app-private `filesDir` and is
shared with an editor through AndroidX `FileProvider`; Greg never exposes a raw
filesystem path.

For ordinary filesystem destinations Greg stages, flushes, and atomically renames
new ciphertext. Android document providers do not expose a universal atomic-rename
API. For those providers Greg keeps the old ciphertext in memory, writes and reads
back the replacement, and attempts to restore the original on failure. If safe
replacement cannot be confirmed, the unlocked session is retained and the UI
offers **Save encrypted copy**.

The Android client implements the documented Argon2id and AES-256-GCM container
format directly using Bouncy Castle, the Android/JCA AES-GCM provider, and Gson.
An immutable cross-platform test vector verifies byte-for-byte compatibility with
the Python desktop implementation.

As on desktop, an external editor can create thumbnails, autosaves, recent-file
entries, caches, or recovery copies outside Greg's control. See the root
[`README.md`](../README.md) and [`docs/FORMAT.md`](../docs/FORMAT.md) for the full
security model and binary format.
