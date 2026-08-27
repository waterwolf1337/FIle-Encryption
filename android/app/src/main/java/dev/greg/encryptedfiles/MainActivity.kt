package dev.greg.encryptedfiles

import android.content.Intent
import android.database.Cursor
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import dev.greg.encryptedfiles.crypto.GregAuthenticationException
import dev.greg.encryptedfiles.crypto.GregFormat
import dev.greg.encryptedfiles.crypto.GregPayload
import dev.greg.encryptedfiles.session.AndroidSession
import dev.greg.encryptedfiles.session.SessionManager
import dev.greg.encryptedfiles.session.SessionRecord
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private lateinit var sessionManager: SessionManager
    private lateinit var encryptButton: Button
    private lateinit var openButton: Button
    private lateinit var progress: ProgressBar
    private lateinit var sessionPanel: View
    private lateinit var sessionTitle: TextView
    private lateinit var sessionStatus: TextView
    private lateinit var saveButton: Button
    private lateinit var cancelButton: Button

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var activeSession: AndroidSession? = null
    private var pendingEncryptedDocument: ByteArray? = null
    private var pendingEncryptedName: String? = null
    private var pendingIncomingUri: Uri? = null
    private var destroyed = false

    private val chooseEncryptSource = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            rememberPermission(uri)
            showPasswordDialog("Encrypt ${queryDisplayName(uri)}", confirm = true) { password ->
                prepareEncryptedDocument(uri, password)
            }
        }
    }

    private val chooseEncryptDestination = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-greg-encrypted"),
    ) { destination ->
        val encrypted = pendingEncryptedDocument
        pendingEncryptedDocument = null
        pendingEncryptedName = null
        if (destination != null && encrypted != null) {
            runTask("Writing encrypted document…", {
                sessionManager.writeNewDocument(destination, encrypted)
            }) {
                Toast.makeText(
                    this,
                    "Encrypted file created. Original kept.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    private val chooseExportDestination = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/x-greg-encrypted"),
    ) { destination ->
        val session = activeSession
        if (destination != null && session != null) {
            if (session.needsPassword) {
                showPasswordDialog("Password required", confirm = false) { password ->
                    exportSession(session, destination, password)
                }
            } else {
                exportSession(session, destination, null)
            }
        }
    }

    private val chooseGregFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            rememberPermission(uri)
            promptToOpen(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()
        sessionManager = SessionManager(applicationContext)

        encryptButton.setOnClickListener {
            if (requireNoActiveSession()) chooseEncryptSource.launch(arrayOf("*/*"))
        }
        openButton.setOnClickListener {
            if (requireNoActiveSession()) chooseGregFile.launch(arrayOf("*/*"))
        }
        saveButton.setOnClickListener { confirmSaveAndLock() }
        cancelButton.setOnClickListener { confirmCancel() }

        pendingIncomingUri = intent.takeIf { it.action == Intent.ACTION_VIEW }?.data
        offerRecoveryOrContinue()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (intent.action == Intent.ACTION_VIEW && intent.data != null) {
            if (requireNoActiveSession()) {
                rememberPermission(intent.data!!, intent.flags)
                promptToOpen(intent.data!!)
            }
        }
    }

    override fun onDestroy() {
        destroyed = true
        if (isChangingConfigurations) activeSession?.clearInMemoryKey()
        executor.shutdown()
        super.onDestroy()
    }

    private fun bindViews() {
        encryptButton = findViewById(R.id.encryptButton)
        openButton = findViewById(R.id.openButton)
        progress = findViewById(R.id.progress)
        sessionPanel = findViewById(R.id.sessionPanel)
        sessionTitle = findViewById(R.id.sessionTitle)
        sessionStatus = findViewById(R.id.sessionStatus)
        saveButton = findViewById(R.id.saveButton)
        cancelButton = findViewById(R.id.cancelButton)
    }

    private fun offerRecoveryOrContinue() {
        val records = sessionManager.recoverableSessions()
        if (records.isEmpty()) {
            handlePendingIncomingUri()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Recovered unlocked session")
            .setMessage(
                "Greg found ${records.size} session(s) left after the app stopped. " +
                    "They may contain plaintext.",
            )
            .setPositiveButton("Recover latest") { _, _ -> recover(records.first()) }
            .setNegativeButton("Remove all") { _, _ ->
                runTask("Removing plaintext…", {
                    sessionManager.removeAllRecoverableSessions()
                }) {
                    handlePendingIncomingUri()
                }
            }
            .setNeutralButton("Later") { _, _ -> handlePendingIncomingUri() }
            .setCancelable(false)
            .show()
    }

    private fun recover(record: SessionRecord) {
        runTask("Recovering session…", { sessionManager.recover(record) }) { session ->
            showSession(session, recovered = true, launchEditor = true)
        }
    }

    private fun handlePendingIncomingUri() {
        val uri = pendingIncomingUri ?: return
        pendingIncomingUri = null
        rememberPermission(uri, intent.flags)
        if (requireNoActiveSession()) promptToOpen(uri)
    }

    private fun prepareEncryptedDocument(source: Uri, password: CharArray) {
        runTask("Encrypting…", {
            try {
                val filename = queryDisplayName(source)
                val bytes = sessionManager.readUri(source)
                filename to GregFormat.encryptNew(GregPayload(filename, bytes), password)
            } finally {
                password.fill('\u0000')
            }
        }) { (filename, encrypted) ->
            pendingEncryptedDocument = encrypted
            pendingEncryptedName = suggestedGregName(filename)
            chooseEncryptDestination.launch(pendingEncryptedName!!)
        }
    }

    private fun promptToOpen(uri: Uri) {
        showPasswordDialog("Unlock ${queryDisplayName(uri)}", confirm = false) { password ->
            runTask("Unlocking…", {
                try {
                    sessionManager.open(uri, password)
                } finally {
                    password.fill('\u0000')
                }
            }) { session ->
                showSession(session, recovered = false, launchEditor = true)
            }
        }
    }

    private fun showSession(
        session: AndroidSession,
        recovered: Boolean,
        launchEditor: Boolean,
    ) {
        activeSession = session
        sessionPanel.visibility = View.VISIBLE
        sessionTitle.text = getString(R.string.session_unlocked, session.plaintextFile.name)
        sessionStatus.text = if (recovered) {
            "Recovered after Greg stopped. Save the external document first; your " +
                "password will be requested again when locking."
        } else {
            "Edit and save in the external app. Return here, preferably close the " +
                "editor, then press Save and lock."
        }
        encryptButton.isEnabled = false
        openButton.isEnabled = false
        if (launchEditor) {
            try {
                session.openExternalEditor()
            } catch (error: Exception) {
                showError("No compatible editor", error)
            }
        }
    }

    private fun confirmSaveAndLock() {
        val session = activeSession ?: return
        AlertDialog.Builder(this)
            .setTitle("Save and lock?")
            .setMessage(
                "Save and preferably close the document in the external editor first. " +
                    "Greg will now encrypt the current temporary file.",
            )
            .setPositiveButton("Save and lock") { _, _ ->
                if (session.needsPassword) {
                    showPasswordDialog("Password required", confirm = false) { password ->
                        saveSession(session, password)
                    }
                } else {
                    saveSession(session, null)
                }
            }
            .setNegativeButton("Not yet", null)
            .show()
    }

    private fun saveSession(session: AndroidSession, password: CharArray?) {
        runTask(
            "Encrypting and verifying…",
            task = {
                try {
                    session.saveAndLock(password)
                } finally {
                    password?.fill('\u0000')
                }
            },
            failure = { error ->
            AlertDialog.Builder(this)
                .setTitle("Could not replace original")
                .setMessage(
                    "The document provider could not safely replace the selected .greg. " +
                        "The unlocked session and original file were kept. You can retry or " +
                        "save the updated encrypted document as a new file.\n\n" +
                        (error.message ?: error.javaClass.simpleName),
                )
                .setPositiveButton("Save encrypted copy") { _, _ ->
                    chooseExportDestination.launch(
                        suggestedGregName(session.plaintextFile.name),
                    )
                }
                .setNegativeButton("Keep session", null)
                .show()
            },
        ) {
            clearSessionUi()
            Toast.makeText(this, "Saved and locked", Toast.LENGTH_LONG).show()
        }
    }

    private fun exportSession(
        session: AndroidSession,
        destination: Uri,
        password: CharArray?,
    ) {
        runTask("Writing encrypted copy…", {
            try {
                session.exportAndLock(destination, password)
            } finally {
                password?.fill('\u0000')
            }
        }) {
            clearSessionUi()
            Toast.makeText(this, "Encrypted copy saved and session locked", Toast.LENGTH_LONG)
                .show()
        }
    }

    private fun confirmCancel() {
        val session = activeSession ?: return
        AlertDialog.Builder(this)
            .setTitle("Discard changes?")
            .setMessage("The existing .greg stays unchanged. Temporary edits are deleted.")
            .setPositiveButton("Discard") { _, _ ->
                runTask("Removing plaintext…", { session.cancel() }) {
                    clearSessionUi()
                }
            }
            .setNegativeButton("Keep editing", null)
            .show()
    }

    private fun clearSessionUi() {
        activeSession = null
        sessionPanel.visibility = View.GONE
        encryptButton.isEnabled = true
        openButton.isEnabled = true
    }

    private fun showPasswordDialog(
        title: String,
        confirm: Boolean,
        accepted: (CharArray) -> Unit,
    ) {
        val password = passwordField("Password")
        val confirmation = if (confirm) passwordField("Confirm password") else null
        val padding = (20 * resources.displayMetrics.density).toInt()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, 0, padding, 0)
            addView(password)
            confirmation?.let(::addView)
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle(title)
            .setView(container)
            .setPositiveButton(if (confirm) "Encrypt" else "Unlock", null)
            .setNegativeButton("Cancel", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val first = password.editableText.toCharArraySecure()
                val second = confirmation?.editableText?.toCharArraySecure()
                when {
                    first.isEmpty() -> {
                        first.fill('\u0000')
                        password.error = "Password is required"
                    }
                    second != null && !first.contentEquals(second) -> {
                        first.fill('\u0000')
                        second.fill('\u0000')
                        confirmation.error = "Passwords do not match"
                    }
                    else -> {
                        second?.fill('\u0000')
                        password.text?.clear()
                        confirmation?.text?.clear()
                        dialog.dismiss()
                        accepted(first)
                    }
                }
            }
        }
        dialog.show()
    }

    private fun passwordField(hintText: String): EditText = EditText(this).apply {
        hint = hintText
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        isSingleLine = true
    }

    private fun queryDisplayName(uri: Uri): String {
        if (uri.scheme == "file") return uri.lastPathSegment ?: "document"
        var cursor: Cursor? = null
        return try {
            cursor = contentResolver.query(
                uri,
                arrayOf(OpenableColumns.DISPLAY_NAME),
                null,
                null,
                null,
            )
            if (cursor?.moveToFirst() == true) {
                cursor.getString(0)?.substringAfterLast('/') ?: "document"
            } else {
                uri.lastPathSegment?.substringAfterLast('/') ?: "document"
            }
        } finally {
            cursor?.close()
        }
    }

    private fun suggestedGregName(original: String): String {
        val dot = original.lastIndexOf('.')
        val base = if (dot > 0) original.substring(0, dot) else original
        return "$base.greg"
    }

    private fun rememberPermission(uri: Uri, sourceFlags: Int = 0) {
        if (uri.scheme != "content") return
        val requested = Intent.FLAG_GRANT_READ_URI_PERMISSION or
            Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        val flags = if (sourceFlags == 0) requested else sourceFlags and requested
        runCatching { contentResolver.takePersistableUriPermission(uri, flags) }
    }

    private fun requireNoActiveSession(): Boolean {
        if (activeSession == null) return true
        Toast.makeText(this, "Lock or cancel the current session first", Toast.LENGTH_LONG).show()
        return false
    }

    private fun setBusy(busy: Boolean, label: String? = null) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        encryptButton.isEnabled = !busy && activeSession == null
        openButton.isEnabled = !busy && activeSession == null
        saveButton.isEnabled = !busy
        cancelButton.isEnabled = !busy
        if (busy && label != null && activeSession != null) sessionStatus.text = label
    }

    private fun <T> runTask(
        label: String,
        task: () -> T,
        failure: ((Exception) -> Unit)? = null,
        success: (T) -> Unit,
    ) {
        setBusy(true, label)
        executor.execute {
            try {
                val result = task()
                mainHandler.post {
                    if (!destroyed) {
                        setBusy(false)
                        success(result)
                    }
                }
            } catch (error: Exception) {
                mainHandler.post {
                    if (!destroyed) {
                        setBusy(false)
                        if (failure != null) {
                            failure(error)
                        } else {
                            val title = when (error) {
                                is GregAuthenticationException -> "Could not authenticate"
                                is IOException -> "Storage operation failed"
                                else -> "Operation failed"
                            }
                            showError(title, error)
                        }
                    }
                }
            }
        }
    }

    private fun showError(title: String, error: Throwable) {
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(error.message ?: error.javaClass.simpleName)
            .setPositiveButton("OK", null)
            .show()
    }
}

private fun CharSequence.toCharArraySecure(): CharArray = CharArray(length) { index -> this[index] }
