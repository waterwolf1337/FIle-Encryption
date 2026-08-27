package dev.greg.encryptedfiles.session

import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import dev.greg.encryptedfiles.crypto.GregFormat
import dev.greg.encryptedfiles.crypto.GregPayload
import dev.greg.encryptedfiles.crypto.KdfParameters
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SessionManagerInstrumentedTest {
    private val fast = KdfParameters(timeCost = 1, memoryCostKib = 8_192, parallelism = 1)

    @Test
    fun testGenericBinaryGregFileResolvesToGreg() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(
                Uri.parse("content://documents/Download/example.greg"),
                "application/octet-stream",
            )
            addCategory(Intent.CATEGORY_DEFAULT)
        }
        val matches = context.packageManager.queryIntentActivities(
            intent,
            PackageManager.MATCH_DEFAULT_ONLY,
        )

        assertTrue(matches.any { it.activityInfo.packageName == context.packageName })
    }

    @Test
    fun testSaveCycleAndRecoveryOnAndroidStorage() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = SessionManager(context)
        manager.removeAllRecoverableSessions()
        val target = File(context.filesDir, "instrumented-cycle.greg")
        target.writeBytes(
            GregFormat.encryptNew(
                GregPayload("mobile.txt", "before".toByteArray()),
                "password".toCharArray(),
                fast,
            ),
        )

        try {
            val firstSession = manager.open(Uri.fromFile(target), "password".toCharArray())
            val sessionDirectory = firstSession.directory
            assertEquals("before", firstSession.plaintextFile.readText())
            firstSession.plaintextFile.writeText("after")
            firstSession.saveAndLock()
            assertTrue(!sessionDirectory.exists())
            GregFormat.unlock(target.readBytes(), "password".toCharArray()).use { reopened ->
                assertEquals("mobile.txt", reopened.payload.filename)
                assertEquals("after", String(reopened.payload.data))
            }

            val interrupted = manager.open(Uri.fromFile(target), "password".toCharArray())
            interrupted.plaintextFile.writeText("after recovery")
            interrupted.clearInMemoryKey()

            val recoveredRecord = SessionManager(context).recoverableSessions().single()
            val recovered = SessionManager(context).recover(recoveredRecord)
            assertTrue(recovered.needsPassword)
            recovered.saveAndLock("password".toCharArray())
            GregFormat.unlock(target.readBytes(), "password".toCharArray()).use { reopened ->
                assertEquals("after recovery", String(reopened.payload.data))
            }
            assertTrue(SessionManager(context).recoverableSessions().isEmpty())
        } finally {
            manager.removeAllRecoverableSessions()
            target.delete()
        }
    }

    @Test
    fun testCancelLeavesEncryptedContainerUntouched() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val manager = SessionManager(context)
        manager.removeAllRecoverableSessions()
        val target = File(context.filesDir, "instrumented-cancel.greg")
        val original = GregFormat.encryptNew(
            GregPayload("cancel.txt", "original".toByteArray()),
            "password".toCharArray(),
            fast,
        )
        target.writeBytes(original)

        try {
            val session = manager.open(Uri.fromFile(target), "password".toCharArray())
            session.plaintextFile.writeText("discard")
            session.cancel()
            assertTrue(original.contentEquals(target.readBytes()))
        } finally {
            manager.removeAllRecoverableSessions()
            target.delete()
        }
    }
}
