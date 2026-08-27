package dev.greg.encryptedfiles.crypto

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val MAGIC = 0x47524547 // GREG
private const val FORMAT_VERSION = 1
private const val KDF_ARGON2ID = 1
private const val CIPHER_AES_256_GCM = 1
private const val HEADER_SIZE = 32
private const val KEY_LENGTH = 32
private const val SALT_LENGTH = 16
private const val NONCE_LENGTH = 12
private const val TAG_LENGTH = 16
private const val MAX_METADATA_LENGTH = 1_048_576
private const val MAX_CIPHERTEXT_LENGTH = 1L shl 40

open class GregFormatException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

class GregAuthenticationException(cause: Throwable? = null) :
    GregFormatException("Wrong password or corrupted Greg file", cause)

data class KdfParameters(
    val timeCost: Int = 3,
    val memoryCostKib: Int = 65_536,
    val parallelism: Int = 4,
) {
    fun validate() {
        require(timeCost in 1..20) { "Unsupported Argon2 time cost" }
        require(parallelism in 1..64) { "Unsupported Argon2 parallelism" }
        require(memoryCostKib in (8 * parallelism)..4_194_304) {
            "Unsupported Argon2 memory cost"
        }
    }
}

data class GregPayload(
    val filename: String,
    val data: ByteArray,
    val metadata: JsonObject = JsonObject(),
) {
    override fun equals(other: Any?): Boolean =
        other is GregPayload &&
            filename == other.filename &&
            data.contentEquals(other.data) &&
            metadata == other.metadata

    override fun hashCode(): Int = 31 * (31 * filename.hashCode() + data.contentHashCode()) +
        metadata.hashCode()
}

data class GregHeader(
    val parameters: KdfParameters,
    val saltLength: Int,
    val nonceLength: Int,
    val ciphertextLength: Long,
)

class UnlockedGreg internal constructor(
    val payload: GregPayload,
    val parameters: KdfParameters,
    val salt: ByteArray,
    private val key: ByteArray,
) : AutoCloseable {
    private var closed = false

    @Synchronized
    fun encrypt(payload: GregPayload = this.payload): ByteArray {
        check(!closed) { "Unlocked Greg key has already been cleared" }
        return GregFormat.encryptWithKey(
            payload,
            key,
            salt,
            SecureRandom().generateSeed(NONCE_LENGTH),
            parameters,
        )
    }

    @Synchronized
    override fun close() {
        if (!closed) {
            key.fill(0)
            closed = true
        }
    }
}

object GregFormat {
    private val gson: Gson = GsonBuilder().disableHtmlEscaping().create()
    private val random = SecureRandom()

    fun encryptNew(
        payload: GregPayload,
        password: CharArray,
        parameters: KdfParameters = KdfParameters(),
    ): ByteArray {
        val salt = ByteArray(SALT_LENGTH).also(random::nextBytes)
        val nonce = ByteArray(NONCE_LENGTH).also(random::nextBytes)
        return encrypt(payload, password, salt, nonce, parameters)
    }

    fun encrypt(
        payload: GregPayload,
        password: CharArray,
        salt: ByteArray,
        nonce: ByteArray,
        parameters: KdfParameters = KdfParameters(),
    ): ByteArray {
        require(salt.size == SALT_LENGTH) { "Greg v1 requires a 16-byte salt" }
        require(nonce.size == NONCE_LENGTH) { "Greg v1 requires a 12-byte nonce" }
        val key = deriveKey(password, salt, parameters)
        return try {
            encryptWithKey(payload, key, salt, nonce, parameters)
        } finally {
            key.fill(0)
        }
    }

    fun unlock(container: ByteArray, password: CharArray): UnlockedGreg {
        val parsed = parseContainer(container)
        val key = deriveKey(password, parsed.salt, parsed.header.parameters)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(TAG_LENGTH * 8, parsed.nonce),
            )
            cipher.updateAAD(parsed.associatedData)
            val plaintext = cipher.doFinal(parsed.ciphertext)
            return UnlockedGreg(
                deserializePayload(plaintext),
                parsed.header.parameters,
                parsed.salt,
                key,
            )
        } catch (error: AEADBadTagException) {
            key.fill(0)
            throw GregAuthenticationException(error)
        } catch (error: GeneralSecurityException) {
            key.fill(0)
            throw GregFormatException("Could not decrypt Greg file", error)
        } catch (error: RuntimeException) {
            key.fill(0)
            throw error
        }
    }

    fun inspect(container: ByteArray): GregHeader = parseContainer(container).header

    internal fun encryptWithKey(
        payload: GregPayload,
        key: ByteArray,
        salt: ByteArray,
        nonce: ByteArray,
        parameters: KdfParameters,
    ): ByteArray {
        parameters.validate()
        val plaintext = serializePayload(payload)
        val header = GregHeader(parameters, salt.size, nonce.size, plaintext.size.toLong() + TAG_LENGTH)
        val headerBytes = serializeHeader(header)
        val associatedData = headerBytes + salt + nonce
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_LENGTH * 8, nonce),
        )
        cipher.updateAAD(associatedData)
        return associatedData + cipher.doFinal(plaintext)
    }

    private fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        parameters: KdfParameters,
    ): ByteArray {
        require(password.isNotEmpty()) { "Password must not be empty" }
        parameters.validate()
        val encoded = StandardCharsets.UTF_8.newEncoder().encode(CharBuffer.wrap(password))
        val passwordBytes = ByteArray(encoded.remaining())
        encoded.get(passwordBytes)
        if (encoded.hasArray()) encoded.array().fill(0)
        return try {
            val generator = Argon2BytesGenerator()
            generator.init(
                Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withIterations(parameters.timeCost)
                    .withMemoryAsKB(parameters.memoryCostKib)
                    .withParallelism(parameters.parallelism)
                    .withSalt(salt)
                    .build(),
            )
            ByteArray(KEY_LENGTH).also { generator.generateBytes(passwordBytes, it) }
        } finally {
            passwordBytes.fill(0)
        }
    }

    private fun serializeHeader(header: GregHeader): ByteArray {
        return ByteBuffer.allocate(HEADER_SIZE).order(ByteOrder.BIG_ENDIAN).apply {
            putInt(MAGIC)
            put(FORMAT_VERSION.toByte())
            put(KDF_ARGON2ID.toByte())
            put(CIPHER_AES_256_GCM.toByte())
            put(0)
            putInt(header.parameters.timeCost)
            putInt(header.parameters.memoryCostKib)
            putInt(header.parameters.parallelism)
            putShort(header.saltLength.toShort())
            putShort(header.nonceLength.toShort())
            putLong(header.ciphertextLength)
        }.array()
    }

    private fun parseHeader(bytes: ByteArray): GregHeader {
        if (bytes.size != HEADER_SIZE) throw GregFormatException("Truncated Greg header")
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        if (buffer.int != MAGIC) throw GregFormatException("Not a Greg encrypted file")
        val version = buffer.get().toInt() and 0xff
        if (version != FORMAT_VERSION) {
            throw GregFormatException("Unsupported Greg format version: $version")
        }
        val kdf = buffer.get().toInt() and 0xff
        val cipher = buffer.get().toInt() and 0xff
        val flags = buffer.get().toInt() and 0xff
        if (kdf != KDF_ARGON2ID || cipher != CIPHER_AES_256_GCM || flags != 0) {
            throw GregFormatException("Unsupported Greg algorithms or flags")
        }
        val parameters = KdfParameters(buffer.int, buffer.int, buffer.int)
        try {
            parameters.validate()
        } catch (error: IllegalArgumentException) {
            throw GregFormatException(error.message ?: "Invalid Argon2 parameters", error)
        }
        val saltLength = buffer.short.toInt() and 0xffff
        val nonceLength = buffer.short.toInt() and 0xffff
        val ciphertextLength = buffer.long
        if (saltLength != SALT_LENGTH || nonceLength != NONCE_LENGTH) {
            throw GregFormatException("Unsupported salt or nonce length")
        }
        if (ciphertextLength !in TAG_LENGTH.toLong()..MAX_CIPHERTEXT_LENGTH) {
            throw GregFormatException("Invalid ciphertext length")
        }
        return GregHeader(parameters, saltLength, nonceLength, ciphertextLength)
    }

    private data class ParsedContainer(
        val header: GregHeader,
        val salt: ByteArray,
        val nonce: ByteArray,
        val ciphertext: ByteArray,
        val associatedData: ByteArray,
    )

    private fun parseContainer(container: ByteArray): ParsedContainer {
        if (container.size < HEADER_SIZE) throw GregFormatException("Truncated Greg file")
        val headerBytes = container.copyOfRange(0, HEADER_SIZE)
        val header = parseHeader(headerBytes)
        val saltEnd = HEADER_SIZE + header.saltLength
        val nonceEnd = saltEnd + header.nonceLength
        val expected = nonceEnd.toLong() + header.ciphertextLength
        if (container.size.toLong() != expected) {
            throw GregFormatException("Greg file length does not match its header")
        }
        return ParsedContainer(
            header,
            container.copyOfRange(HEADER_SIZE, saltEnd),
            container.copyOfRange(saltEnd, nonceEnd),
            container.copyOfRange(nonceEnd, container.size),
            container.copyOfRange(0, nonceEnd),
        )
    }

    private fun serializePayload(payload: GregPayload): ByteArray {
        validateFilename(payload.filename)
        val root = JsonObject().apply {
            addProperty("extension", extensionOf(payload.filename))
            addProperty("filename", payload.filename)
            add("metadata", payload.metadata.deepCopy())
        }
        val json = gson.toJson(root).toByteArray(StandardCharsets.UTF_8)
        require(json.size <= MAX_METADATA_LENGTH) { "Payload metadata is too large" }
        return ByteBuffer.allocate(4 + json.size + payload.data.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(json.size)
            .put(json)
            .put(payload.data)
            .array()
    }

    private fun deserializePayload(plaintext: ByteArray): GregPayload {
        if (plaintext.size < 4) throw GregFormatException("Truncated encrypted payload")
        val buffer = ByteBuffer.wrap(plaintext).order(ByteOrder.BIG_ENDIAN)
        val metadataLength = buffer.int
        if (metadataLength !in 0..MAX_METADATA_LENGTH || metadataLength > buffer.remaining()) {
            throw GregFormatException("Invalid encrypted payload metadata length")
        }
        val metadataBytes = ByteArray(metadataLength).also(buffer::get)
        val root = try {
            JsonParser.parseString(String(metadataBytes, StandardCharsets.UTF_8)).asJsonObject
        } catch (error: RuntimeException) {
            throw GregFormatException("Invalid encrypted payload metadata", error)
        }
        val filename = root.get("filename")?.takeIf { it.isJsonPrimitive }?.asString
            ?: throw GregFormatException("Missing encrypted filename")
        val extension = root.get("extension")?.takeIf { it.isJsonPrimitive }?.asString
            ?: throw GregFormatException("Missing encrypted extension")
        val metadata = root.get("metadata")?.takeIf { it.isJsonObject }?.asJsonObject
            ?: JsonObject()
        validateFilename(filename)
        if (extension != extensionOf(filename)) {
            throw GregFormatException("Inconsistent encrypted extension metadata")
        }
        return GregPayload(filename, ByteArray(buffer.remaining()).also(buffer::get), metadata)
    }

    private fun validateFilename(filename: String) {
        if (
            filename.isEmpty() || filename == "." || filename == ".." ||
            '\u0000' in filename || '/' in filename || '\\' in filename
        ) {
            throw GregFormatException("Unsafe original filename")
        }
    }

    private fun extensionOf(filename: String): String {
        val index = filename.lastIndexOf('.')
        return if (index > 0 && index < filename.lastIndex) filename.substring(index) else ""
    }
}
