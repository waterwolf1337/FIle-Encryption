package dev.greg.encryptedfiles.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test

class GregFormatTest {
    private val fast = KdfParameters(timeCost = 1, memoryCostKib = 8_192, parallelism = 1)

    @Test
    fun roundTripPreservesFilenameAndBytes() {
        val payload = GregPayload("finances.xlsx", byteArrayOf(0, 1, 2, 127, -1))
        val container = GregFormat.encryptNew(payload, "correct horse".toCharArray(), fast)

        GregFormat.unlock(container, "correct horse".toCharArray()).use { opened ->
            assertEquals("finances.xlsx", opened.payload.filename)
            assertArrayEquals(payload.data, opened.payload.data)
        }
    }

    @Test
    fun wrongPasswordFailsAuthentication() {
        val container = GregFormat.encryptNew(
            GregPayload("notes.txt", "secret".toByteArray()),
            "right".toCharArray(),
            fast,
        )

        expectThrows<GregAuthenticationException> {
            GregFormat.unlock(container, "wrong".toCharArray())
        }
    }

    @Test
    fun corruptedCiphertextFailsAuthentication() {
        val container = GregFormat.encryptNew(
            GregPayload("notes.txt", "secret".toByteArray()),
            "right".toCharArray(),
            fast,
        )
        container[container.lastIndex] = (container.last() + 1).toByte()

        expectThrows<GregAuthenticationException> {
            GregFormat.unlock(container, "right".toCharArray())
        }
    }

    @Test
    fun identicalEncryptionsDiffer() {
        val payload = GregPayload("same.pdf", "same".toByteArray())
        val first = GregFormat.encryptNew(payload, "password".toCharArray(), fast)
        val second = GregFormat.encryptNew(payload, "password".toCharArray(), fast)

        assertFalse(first.contentEquals(second))
    }

    @Test
    fun unsupportedVersionIsRejected() {
        val container = GregFormat.encryptNew(
            GregPayload("a.bin", byteArrayOf(1)),
            "password".toCharArray(),
            fast,
        )
        container[4] = 99

        val error = expectThrows<GregFormatException> {
            GregFormat.inspect(container)
        }
        assertEquals("Unsupported Greg format version: 99", error.message)
    }

    @Test
    fun deterministicEncryptionMatchesDesktopVector() {
        val salt = ByteArray(16) { it.toByte() }
        val nonce = ByteArray(12) { (it + 16).toByte() }
        val container = GregFormat.encrypt(
            GregPayload("interop.txt", "Hello from Greg\n".toByteArray()),
            "interop-password".toCharArray(),
            salt,
            nonce,
            fast,
        )

        assertEquals(DESKTOP_VECTOR_HEX, container.toHex())
    }

    @Test
    fun containerProducedByDesktopDecryptsOnAndroid() {
        GregFormat.unlock(DESKTOP_VECTOR_HEX.hexToBytes(), "interop-password".toCharArray())
            .use { opened ->
                assertEquals("interop.txt", opened.payload.filename)
                assertArrayEquals("Hello from Greg\n".toByteArray(), opened.payload.data)
            }
    }

    @Test
    fun unsafeFilenameCannotBeEncrypted() {
        expectThrows<GregFormatException> {
            GregFormat.encryptNew(
                GregPayload("../escape.txt", byteArrayOf(1)),
                "password".toCharArray(),
                fast,
            )
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun String.hexToBytes(): ByteArray = chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    private inline fun <reified T : Throwable> expectThrows(block: () -> Unit): T {
        try {
            block()
        } catch (error: Throwable) {
            if (error is T) return error
            throw error
        }
        fail("Expected ${T::class.java.simpleName}")
        throw AssertionError("unreachable")
    }

    companion object {
        // Filled from the Python desktop implementation and intentionally immutable.
        private const val DESKTOP_VECTOR_HEX =
            "47524547010101000000000100002000000000010010000c000000000000005f" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b905291e8" +
                "58f3b367254c0d898c1b86636c2adb027cf811bde2f533c4f1686adcdc50826" +
                "d8493df590d9368aeee0cf1a670e30301a82b6c5a69857bfe1020669e67db0f" +
                "a4c87dde7fefec70b46e9f769b6847679acfedb9aabc4294ae631b03"
    }
}
