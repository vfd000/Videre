package com.github.dvbeckwitt.videre.proxy

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import org.json.JSONArray
import org.json.JSONObject

/** The stored PKCS#12 bytes, its password and the hosts it is presented to. */
internal class ClientCertificateMaterial(
    val pkcs12: ByteArray,
    val password: String,
    val hosts: List<String>,
) {
    val identity: ClientIdentity by lazy { ClientIdentity.fromPkcs12(pkcs12, password.toCharArray()) }
}

/**
 * Keeps one mTLS client certificate in app-private storage, encrypted with an
 * AES-GCM key that never leaves the Android Keystore. The password and key are
 * never logged or returned in error messages.
 */
object ClientCertificates {
    private const val KEY_ALIAS = "videre_client_certificate"
    private const val FILE_NAME = "videre_client_certificate.bin"
    private var file: File? = null
    private var material: ClientCertificateMaterial? = null
    private var tls: ClientCertificateTls? = null
    private var loadError: String? = null

    @Synchronized
    internal fun initialize(context: Context) {
        if (file != null) return
        val target = File(context.applicationContext.filesDir, FILE_NAME)
        file = target
        if (!target.exists()) return
        try {
            val json = JSONObject(String(decrypt(target.readBytes()), Charsets.UTF_8))
            val hosts = json.getJSONArray("hosts").let { array -> (0 until array.length()).map(array::getString) }
            val loaded = ClientCertificateMaterial(
                Base64.decode(json.getString("pkcs12"), Base64.NO_WRAP), json.getString("password"), hosts)
            tls = ClientCertificateTls(loaded.identity, loaded.hosts)
            material = loaded
        } catch (_: Exception) {
            // A restored backup or reset Keystore cannot decrypt the old file.
            // Report it in settings; requests continue without a certificate.
            loadError = "unreadable"
        }
    }

    /** Parses without saving, for showing the subject and expiry before import. */
    fun inspect(pkcs12: ByteArray, password: String): Map<String, Any> =
        ClientIdentity.fromPkcs12(pkcs12, password.toCharArray()).describe(emptyList())

    @Synchronized
    internal fun save(pkcs12: ByteArray, password: String, hosts: List<String>): Map<String, Any> {
        val normalized = normalizeHosts(hosts)
        val next = ClientCertificateMaterial(pkcs12, password, normalized)
        val nextTls = ClientCertificateTls(next.identity, normalized)
        write(next)
        material = next
        tls = nextTls
        loadError = null
        return status()
    }

    @Synchronized
    internal fun setHosts(hosts: List<String>): Map<String, Any> {
        val current = material ?: throw ClientCertificateException("missing")
        return save(current.pkcs12, current.password, hosts)
    }

    @Synchronized
    internal fun remove() {
        val target = checkNotNull(file) { "Client certificates are not initialized." }
        if (target.exists() && !target.delete()) throw ClientCertificateException("storage")
        material = null
        tls = null
        loadError = null
    }

    @Synchronized
    internal fun status(): Map<String, Any> {
        val current = material ?: return if (loadError != null) mapOf("error" to loadError!!) else emptyMap()
        return current.identity.describe(current.hosts)
    }

    /** Raw material for the Dart transport's SecurityContext, in-process only. */
    @Synchronized
    internal fun dartMaterial(): Map<String, Any>? = material?.let {
        mapOf("pkcs12" to it.pkcs12, "password" to it.password, "hosts" to it.hosts)
    }

    @Synchronized
    internal fun tls(): ClientCertificateTls? = tls

    /** The key and chain for a WebView client-certificate request, or null when
     * this host is not selected. */
    @Synchronized
    fun identityFor(host: String?): ClientIdentity? {
        val current = material ?: return null
        return if (clientCertificateHostSelected(current.hosts, host)) current.identity else null
    }

    private fun normalizeHosts(hosts: List<String>): List<String> = hosts.map {
        normalizeCertificateHostPattern(it) ?: throw ClientCertificateException("invalidHost")
    }.distinct()

    private fun write(value: ClientCertificateMaterial) {
        val target = checkNotNull(file) { "Client certificates are not initialized." }
        val json = JSONObject()
            .put("pkcs12", Base64.encodeToString(value.pkcs12, Base64.NO_WRAP))
            .put("password", value.password)
            .put("hosts", JSONArray(value.hosts))
        val temporary = File(target.parentFile, "$FILE_NAME.tmp")
        try {
            temporary.writeBytes(encrypt(json.toString().toByteArray(Charsets.UTF_8)))
            if (!temporary.renameTo(target)) throw ClientCertificateException("storage")
        } catch (error: ClientCertificateException) {
            temporary.delete()
            throw error
        } catch (_: Exception) {
            temporary.delete()
            throw ClientCertificateException("storage")
        }
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
        }.generateKey()
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val iv = cipher.iv
        return byteArrayOf(1, iv.size.toByte()) + iv + cipher.doFinal(plain)
    }

    private fun decrypt(stored: ByteArray): ByteArray {
        require(stored.size > 2 && stored[0] == 1.toByte()) { "Unknown client certificate format." }
        val ivLength = stored[1].toInt()
        require(ivLength in 12..16 && stored.size > 2 + ivLength)
        val iv = stored.copyOfRange(2, 2 + ivLength)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv))
        }
        return cipher.doFinal(stored, 2 + ivLength, stored.size - 2 - ivLength)
    }
}
