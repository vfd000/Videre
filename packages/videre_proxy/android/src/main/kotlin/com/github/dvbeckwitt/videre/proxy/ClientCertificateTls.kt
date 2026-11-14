package com.github.dvbeckwitt.videre.proxy

import java.io.ByteArrayInputStream
import java.io.IOException
import java.net.Socket
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.Principal
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager
import javax.security.auth.x500.X500Principal

/** Why a PKCS#12 file could not be used. Never carries the password. */
class ClientCertificateException(val reason: String) : Exception(reason)

/** The private key and certificate chain from one PKCS#12 file. */
class ClientIdentity(val privateKey: PrivateKey, val chain: Array<X509Certificate>) {
    val certificate: X509Certificate get() = chain.first()

    val subjectName: String get() = certificate.subjectX500Principal.getName(X500Principal.RFC2253)

    /** The subject common name, falling back to the full subject. */
    val commonName: String get() = commonNameOf(subjectName) ?: subjectName

    fun describe(hosts: Collection<String>): Map<String, Any> = mapOf(
        "subject" to subjectName,
        "commonName" to commonName,
        "issuer" to certificate.issuerX500Principal.getName(X500Principal.RFC2253),
        "notBefore" to certificate.notBefore.time,
        "notAfter" to certificate.notAfter.time,
        "hosts" to hosts.toList(),
    )

    companion object {
        /** Loads the first key entry with the platform PKCS#12 provider. */
        fun fromPkcs12(bytes: ByteArray, password: CharArray): ClientIdentity {
            if (bytes.isEmpty() || bytes.size > MAX_PKCS12_BYTES) throw ClientCertificateException("invalidFile")
            val store = try {
                KeyStore.getInstance("PKCS12").apply { load(ByteArrayInputStream(bytes), password) }
            } catch (error: IOException) {
                throw ClientCertificateException(if (isPasswordError(error)) "wrongPassword" else "unsupported")
            } catch (_: GeneralSecurityException) {
                throw ClientCertificateException("unsupported")
            } catch (_: RuntimeException) {
                // Malformed DER can surface as unchecked parser errors.
                throw ClientCertificateException("invalidFile")
            }
            try {
                for (alias in store.aliases().toList()) {
                    if (!store.isKeyEntry(alias)) continue
                    val key = store.getKey(alias, password) as? PrivateKey ?: continue
                    val chain = store.getCertificateChain(alias)?.mapNotNull { it as? X509Certificate }
                    if (chain.isNullOrEmpty()) continue
                    return ClientIdentity(key, chain.toTypedArray())
                }
            } catch (_: UnrecoverableKeyException) {
                throw ClientCertificateException("wrongPassword")
            } catch (_: GeneralSecurityException) {
                throw ClientCertificateException("unsupported")
            }
            throw ClientCertificateException("noKey")
        }

        private fun isPasswordError(error: Throwable): Boolean =
            generateSequence(error) { it.cause }.take(8).any {
                it is UnrecoverableKeyException || it.message?.contains("password", ignoreCase = true) == true ||
                    it.message?.contains("mac", ignoreCase = true) == true
            }

        internal fun commonNameOf(rfc2253: String): String? {
            var index = 0
            while (index < rfc2253.length) {
                // RDNs are comma separated; a backslash escapes the next character.
                val start = index
                var escaped = false
                while (index < rfc2253.length) {
                    val char = rfc2253[index]
                    if (escaped) escaped = false
                    else if (char == '\\') escaped = true
                    else if (char == ',' || char == '+') break
                    index++
                }
                val part = rfc2253.substring(start, index).trim()
                if (part.startsWith("CN=", ignoreCase = true)) {
                    return part.substring(3).replace(Regex("""\\(.)"""), "$1").takeIf { it.isNotEmpty() }
                }
                index++
            }
            return null
        }

        const val MAX_PKCS12_BYTES = 1024 * 1024
    }
}

/** Lower-cases and strips a trailing dot. Returns null for anything that is
 * not an ASCII host name or IP literal (use punycode for IDN hosts). */
fun normalizeCertificateHost(input: String): String? {
    val host = input.trim().removeSurrounding("[", "]").trimEnd('.').lowercase(Locale.ROOT)
    if (host.isEmpty() || host.length > 253) return null
    if (host.contains(':')) {
        return host.takeIf { value -> value.all { it in '0'..'9' || it in 'a'..'f' || it == ':' || it == '.' } }
    }
    return host.takeIf { value ->
        value.all { it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '.' || it == '_' } &&
            value.split('.').none(String::isEmpty)
    }
}

/** A selected host: an exact host, or "*.example.com" for its subdomains. */
fun normalizeCertificateHostPattern(input: String): String? {
    val value = input.trim()
    if (value.startsWith("*.")) return normalizeCertificateHost(value.substring(2))?.let { "*.$it" }
    return normalizeCertificateHost(value)
}

fun clientCertificateHostSelected(patterns: Collection<String>, host: String?): Boolean {
    val target = host?.let(::normalizeCertificateHost) ?: return false
    return patterns.any { pattern ->
        if (pattern.startsWith("*.")) target.endsWith(pattern.substring(1))
        else pattern == target
    }
}

/** Offers the client certificate only during handshakes with selected hosts.
 * Any other server that asks for a certificate gets none. */
class HostScopedKeyManager(
    private val identity: ClientIdentity,
    hosts: Collection<String>,
) : X509ExtendedKeyManager() {
    private val hosts = hosts.mapNotNull(::normalizeCertificateHostPattern).toSet()
    private val keyType = identity.privateKey.algorithm.uppercase(Locale.ROOT)

    private fun aliasFor(keyTypes: Array<out String>?, host: String?): String? {
        if (!clientCertificateHostSelected(hosts, host)) return null
        val types = keyTypes?.map { it.uppercase(Locale.ROOT) }
        // TLS 1.2 may ask for "EC" or "EC_EC"; TLS 1.3 passes signature families.
        if (types != null && types.none { it == keyType || it.startsWith("${keyType}_") ||
                (keyType == "EC" && it == "ECDSA") }) return null
        return ALIAS
    }

    override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?): String? =
        aliasFor(keyType, peerHost(socket))

    override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?): String? =
        aliasFor(keyType, engine?.peerHost)

    override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?): Array<String> = arrayOf(ALIAS)

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias == ALIAS) identity.chain.clone() else null

    override fun getPrivateKey(alias: String?): PrivateKey? = if (alias == ALIAS) identity.privateKey else null

    override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?): Array<String>? = null

    override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?): String? = null

    companion object {
        const val ALIAS = "videre-client-certificate"

        /** The host OkHttp connected to: the handshake peer, else the SNI name. */
        internal fun peerHost(socket: Socket?): String? {
            val ssl = socket as? SSLSocket ?: return null
            runCatching { ssl.handshakeSession?.peerHost }.getOrNull()?.let { return it }
            runCatching {
                ssl.sslParameters?.serverNames?.firstNotNullOfOrNull { (it as? SNIHostName)?.asciiName }
            }.getOrNull()?.let { return it }
            return null
        }
    }
}

/** TLS settings for OkHttp: platform trust plus the host-scoped client key. */
class ClientCertificateTls(identity: ClientIdentity, hosts: Collection<String>) {
    val keyManager = HostScopedKeyManager(identity, hosts)
    val trustManager: X509TrustManager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        .apply { init(null as KeyStore?) }.trustManagers.filterIsInstance<X509TrustManager>().first()
    val socketFactory: SSLSocketFactory = SSLContext.getInstance("TLS").apply {
        init(arrayOf(keyManager), arrayOf(trustManager), null)
    }.socketFactory
}
