package dev.greg.encryptedfiles.session

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import androidx.core.net.toUri
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.reflect.TypeToken
import dev.greg.encryptedfiles.crypto.GregFormat
import dev.greg.encryptedfiles.crypto.GregPayload
import dev.greg.encryptedfiles.crypto.UnlockedGreg
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.UUID

private const val SESSION_ROOT = "unlocked-sessions"
private const val SESSION_PREFIX = "greg-session-"
private const val MARKER_PREFIX = ".greg-owner-"
private const val REGISTRY_FILE = "android-sessions.json"
private const val APP_MARKER = "greg-encrypted-files-android-v1"

data class SessionRecord(
    val sessionId: String,
    val sourceUri: String,
    val createdAt: Long,
)

class AndroidSession internal constructor(
    private val context: Context,
    private val manager: SessionManager,
    val record: SessionRecord,
    val directory: File,
    val plaintextFile: File,
    private var unlocked: UnlockedGreg?,
) {
    val needsPassword: Boolean get() = unlocked == null
    private var ended = false

    fun openExternalEditor() {
        ensureActive()
        val uri = FileProvider.getUriForFile(
            context,
            "${context.packageName}.files",
            plaintextFile,
        )
        val extension = plaintextFile.extension.lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
            ?: "application/octet-stream"
        val editIntent = Intent(Intent.ACTION_EDIT).apply {
            setDataAndType(uri, mime)
            clipData = ClipData.newRawUri(plaintextFile.name, uri)
            addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION or
                    Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        }
        val launchIntent = if (editIntent.resolveActivity(context.packageManager) != null) {
            Intent.createChooser(editIntent, "Edit ${plaintextFile.name}")
        } else {
            Intent.createChooser(
                Intent(Intent.ACTION_VIEW).apply {
                    setDataAndType(uri, mime)
                    clipData = ClipData.newRawUri(plaintextFile.name, uri)
                    addFlags(
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or
                            Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                    )
                },
                "Open ${plaintextFile.name}",
            )
        }
        context.startActivity(launchIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun saveAndLock(passwordForRecovery: CharArray? = null) {
        ensureActive()
        val ciphertext = buildUpdatedCiphertext(passwordForRecovery)
        manager.replaceAndVerify(record.sourceUri.toUri(), ciphertext, directory)
        finish()
    }

    fun exportAndLock(destination: Uri, passwordForRecovery: CharArray? = null) {
        ensureActive()
        val ciphertext = buildUpdatedCiphertext(passwordForRecovery)
        manager.writeNewDocument(destination, ciphertext)
        finish()
    }

    private fun buildUpdatedCiphertext(passwordForRecovery: CharArray?): ByteArray {
        var contextToClose: UnlockedGreg? = null
        val encryptionContext = unlocked ?: run {
            require(passwordForRecovery != null) { "Password is required after recovery" }
            val restored = GregFormat.unlock(
                manager.readUri(record.sourceUri.toUri()),
                passwordForRecovery,
            )
            if (restored.payload.filename != plaintextFile.name) {
                restored.close()
                throw IOException("The encrypted source no longer matches this session")
            }
            contextToClose = restored
            restored
        }
        try {
            waitForFileToSettle(plaintextFile)
            val updatedPayload = GregPayload(
                encryptionContext.payload.filename,
                plaintextFile.readBytes(),
                encryptionContext.payload.metadata,
            )
            return encryptionContext.encrypt(updatedPayload)
        } finally {
            contextToClose?.close()
        }
    }

    fun cancel() {
        ensureActive()
        finish()
    }

    fun clearInMemoryKey() {
        unlocked?.close()
        unlocked = null
    }

    private fun finish() {
        unlocked?.close()
        unlocked = null
        manager.removeSession(record, directory)
        ended = true
    }

    private fun ensureActive() {
        check(!ended) { "Greg session has already ended" }
    }
}

class SessionManager(private val context: Context) {
    private val gson: Gson = GsonBuilder().disableHtmlEscaping().create()
    private val root = File(context.filesDir, SESSION_ROOT)
    private val registry = File(context.filesDir, REGISTRY_FILE)

    init {
        root.mkdirs()
    }

    fun open(source: Uri, password: CharArray): AndroidSession {
        val unlocked = GregFormat.unlock(readUri(source), password)
        val id = UUID.randomUUID().toString().replace("-", "")
        val directory = File(root, "$SESSION_PREFIX$id")
        try {
            if (!directory.mkdir()) throw IOException("Could not create private session")
            val marker = File(directory, "$MARKER_PREFIX$id")
            marker.writeText(
                gson.toJson(mapOf("application" to APP_MARKER, "sessionId" to id)),
            )
            val plaintext = File(directory, unlocked.payload.filename)
            FileOutputStream(plaintext).use { output ->
                output.write(unlocked.payload.data)
                output.flush()
                output.fd.sync()
            }
            val record = SessionRecord(id, source.toString(), System.currentTimeMillis())
            writeRecords(readRecords() + record)
            return AndroidSession(context, this, record, directory, plaintext, unlocked)
        } catch (error: Exception) {
            unlocked.close()
            directory.deleteRecursively()
            throw error
        }
    }

    fun recover(record: SessionRecord): AndroidSession {
        val directory = verifiedDirectory(record)
            ?: throw IOException("The recovered Greg session is no longer available")
        val plaintext = directory.listFiles()
            ?.singleOrNull { it.isFile && !it.name.startsWith(MARKER_PREFIX) }
            ?: throw IOException("Recovered Greg session has invalid contents")
        return AndroidSession(context, this, record, directory, plaintext, null)
    }

    fun recoverableSessions(): List<SessionRecord> {
        val valid = readRecords().filter { verifiedDirectory(it) != null }
        if (valid.size != readRecords().size) writeRecords(valid)
        return valid.sortedByDescending(SessionRecord::createdAt)
    }

    fun removeAllRecoverableSessions() {
        readRecords().forEach { record ->
            verifiedDirectory(record)?.deleteRecursively()
        }
        writeRecords(emptyList())
        root.listFiles()
            ?.filter { it.isDirectory && it.name.startsWith(SESSION_PREFIX) }
            ?.forEach { candidate ->
                val marker = candidate.listFiles()?.any { markerMatches(it, null) } == true
                if (marker) candidate.deleteRecursively()
            }
    }

    internal fun removeSession(record: SessionRecord, directory: File) {
        val verified = verifiedDirectory(record)
            ?: throw IOException("Refusing to remove an unverified session directory")
        if (!verified.deleteRecursively()) {
            throw IOException("Could not remove temporary plaintext")
        }
        writeRecords(readRecords().filterNot { it.sessionId == record.sessionId })
    }

    internal fun readUri(uri: Uri): ByteArray {
        return if (uri.scheme == "file") {
            File(requireNotNull(uri.path)).readBytes()
        } else {
            context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IOException("Could not read selected document")
        }
    }

    fun writeNewDocument(uri: Uri, bytes: ByteArray) {
        writeUri(uri, bytes)
        if (!readUri(uri).contentEquals(bytes)) {
            throw IOException("The document provider did not preserve the encrypted file")
        }
    }

    internal fun replaceAndVerify(uri: Uri, bytes: ByteArray, sessionDirectory: File) {
        if (uri.scheme == "file") {
            replaceFileAtomically(uri, bytes)
            return
        }
        val oldCiphertext = readUri(uri)
        val staged = File(sessionDirectory, ".replacement.greg")
        FileOutputStream(staged).use { output ->
            output.write(bytes)
            output.flush()
            output.fd.sync()
        }
        try {
            writeUri(uri, staged.readBytes())
            if (!readUri(uri).contentEquals(bytes)) {
                throw IOException("The document provider returned different data after saving")
            }
        } catch (saveError: Exception) {
            try {
                writeUri(uri, oldCiphertext)
            } catch (restoreError: Exception) {
                saveError.addSuppressed(restoreError)
            }
            throw IOException(
                "Could not safely replace the Greg document; the recovery session was kept",
                saveError,
            )
        } finally {
            staged.delete()
        }
    }

    private fun replaceFileAtomically(uri: Uri, bytes: ByteArray) {
        val target = File(requireNotNull(uri.path)).canonicalFile
        val parent = target.parentFile
            ?: throw IOException("Encrypted document has no parent directory")
        val staged = File.createTempFile(".${target.name}.", ".tmp", parent)
        try {
            FileOutputStream(staged).use { output ->
                output.write(bytes)
                output.flush()
                output.fd.sync()
            }
            try {
                Files.move(
                    staged.toPath(),
                    target.toPath(),
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING,
                )
            } catch (error: Exception) {
                throw IOException("Could not atomically replace the Greg document", error)
            }
            if (!target.readBytes().contentEquals(bytes)) {
                throw IOException("The encrypted file differed after replacement")
            }
        } finally {
            staged.delete()
        }
    }

    private fun writeUri(uri: Uri, bytes: ByteArray) {
        if (uri.scheme == "file") {
            File(requireNotNull(uri.path)).outputStream().use { output ->
                output.write(bytes)
                output.flush()
            }
            return
        }
        val descriptor = context.contentResolver.openFileDescriptor(uri, "rwt")
            ?: throw IOException("Could not open selected document for writing")
        descriptor.use {
            FileOutputStream(it.fileDescriptor).use { output ->
                output.write(bytes)
                output.flush()
                output.fd.sync()
            }
        }
    }

    private fun verifiedDirectory(record: SessionRecord): File? {
        val directory = File(root, "$SESSION_PREFIX${record.sessionId}")
        val expectedParent = runCatching { root.canonicalFile }.getOrNull() ?: return null
        val canonical = runCatching { directory.canonicalFile }.getOrNull() ?: return null
        if (!canonical.isDirectory || canonical.parentFile != expectedParent) return null
        return canonical.takeIf {
            markerMatches(File(it, "$MARKER_PREFIX${record.sessionId}"), record.sessionId)
        }
    }

    private fun markerMatches(file: File, expectedId: String?): Boolean {
        if (!file.isFile || !file.name.startsWith(MARKER_PREFIX)) return false
        return runCatching {
            val root = gson.fromJson(file.readText(), Map::class.java)
            val id = root["sessionId"] as? String
            root["application"] == APP_MARKER &&
                id != null && file.name == "$MARKER_PREFIX$id" &&
                (expectedId == null || expectedId == id)
        }.getOrDefault(false)
    }

    private fun readRecords(): List<SessionRecord> {
        if (!registry.isFile) return emptyList()
        return runCatching {
            val type = object : TypeToken<List<SessionRecord>>() {}.type
            gson.fromJson<List<SessionRecord>>(registry.readText(), type) ?: emptyList()
        }.getOrDefault(emptyList())
    }

    private fun writeRecords(records: List<SessionRecord>) {
        val temporary = File(context.filesDir, "$REGISTRY_FILE.tmp")
        FileOutputStream(temporary).use { output ->
            output.write(gson.toJson(records).toByteArray())
            output.flush()
            output.fd.sync()
        }
        try {
            Files.move(
                temporary.toPath(),
                registry.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (error: Exception) {
            temporary.delete()
            throw IOException("Could not update Greg recovery registry", error)
        }
    }
}

private fun waitForFileToSettle(file: File, timeoutMillis: Long = 2_000) {
    val deadline = System.currentTimeMillis() + timeoutMillis
    var previous: Pair<Long, Long>? = null
    var stable = 0
    while (System.currentTimeMillis() < deadline) {
        val observation = file.length() to file.lastModified()
        if (observation == previous) {
            stable += 1
            if (stable >= 2) return
        } else {
            previous = observation
            stable = 0
        }
        Thread.sleep(200)
    }
}
