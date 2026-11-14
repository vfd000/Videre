package com.github.dvbeckwitt.videre.proxy

import java.net.Socket
import javax.net.ssl.SSLContext
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

// Fixtures are self-signed and non-sensitive (src/test/resources):
// client_legacy.p12 is SHA1 MAC + PBE-SHA1-3DES (RSA key, CN=videre-test-client);
// client_aes.p12 is OpenSSL 3's PBES2 AES-256-CBC + HMAC-SHA256 (EC key).
class ClientCertificateTlsTest {
    private val password = "test-password".toCharArray()

    private fun fixture(name: String): ByteArray =
        checkNotNull(javaClass.classLoader?.getResourceAsStream(name)) { "missing $name" }.use { it.readBytes() }

    private fun engine(host: String) = SSLContext.getDefault().createSSLEngine(host, 443)

    @Test
    fun `loads the Android-compatible legacy PKCS12`() {
        val identity = ClientIdentity.fromPkcs12(fixture("client_legacy.p12"), password)
        assertEquals("videre-test-client", identity.commonName)
        assertEquals("RSA", identity.privateKey.algorithm)
        assertEquals(1, identity.chain.size)
        val details = identity.describe(listOf("watch.liess.tv"))
        assertEquals(listOf("watch.liess.tv"), details["hosts"])
        assertEquals(identity.certificate.notAfter.time, details["notAfter"])
    }

    @Test
    fun `loads a modern AES PKCS12 when the platform supports it`() {
        val identity = ClientIdentity.fromPkcs12(fixture("client_aes.p12"), password)
        assertEquals("videre-ec-client", identity.commonName)
        assertEquals("EC", identity.privateKey.algorithm)
    }

    @Test
    fun `reports a wrong password and invalid files without the password`() {
        val wrong = assertThrows(ClientCertificateException::class.java) {
            ClientIdentity.fromPkcs12(fixture("client_legacy.p12"), "nope".toCharArray())
        }
        assertEquals("wrongPassword", wrong.reason)
        assertFalse(wrong.message!!.contains("nope"))
        val invalid = assertThrows(ClientCertificateException::class.java) {
            ClientIdentity.fromPkcs12(byteArrayOf(1, 2, 3, 4), password)
        }
        assertTrue(invalid.reason in setOf("invalidFile", "unsupported"))
        assertEquals("invalidFile", assertThrows(ClientCertificateException::class.java) {
            ClientIdentity.fromPkcs12(ByteArray(0), password)
        }.reason)
    }

    @Test
    fun `offers the certificate only to selected hosts`() {
        val identity = ClientIdentity.fromPkcs12(fixture("client_legacy.p12"), password)
        val manager = HostScopedKeyManager(identity, listOf("Watch.Liess.TV.", "*.example.com"))
        val rsa = arrayOf("RSA")

        val alias = manager.chooseEngineClientAlias(rsa, null, engine("watch.liess.tv"))
        assertEquals(HostScopedKeyManager.ALIAS, alias)
        assertNotNull(manager.getPrivateKey(alias))
        assertArrayEquals(identity.chain, manager.getCertificateChain(alias))
        assertEquals(HostScopedKeyManager.ALIAS, manager.chooseEngineClientAlias(rsa, null, engine("cdn.example.com")))

        for (other in listOf("liess.tv", "evil-watch.liess.tv", "watch.liess.tv.evil.com", "example.com",
                "notexample.com", "youtube.com")) {
            assertNull(other, manager.chooseEngineClientAlias(rsa, null, engine(other)))
        }
        // No peer, no certificate: an unknown destination never receives it.
        assertNull(manager.chooseEngineClientAlias(rsa, null, null))
        assertNull(manager.chooseClientAlias(rsa, null, null))
        assertNull(manager.chooseClientAlias(rsa, null, Socket()))
        // A server asking only for another key type gets nothing.
        assertNull(manager.chooseEngineClientAlias(arrayOf("EC"), null, engine("watch.liess.tv")))
        assertNull(manager.getPrivateKey("other"))
        assertNull(manager.chooseServerAlias("RSA", null, null))
    }

    @Test
    fun `matches EC keys for TLS 1_3 and 1_2 key types`() {
        val identity = ClientIdentity.fromPkcs12(fixture("client_aes.p12"), password)
        val manager = HostScopedKeyManager(identity, listOf("watch.liess.tv"))
        assertEquals(HostScopedKeyManager.ALIAS,
            manager.chooseEngineClientAlias(arrayOf("RSA", "EC"), null, engine("watch.liess.tv")))
        assertEquals(HostScopedKeyManager.ALIAS,
            manager.chooseEngineClientAlias(arrayOf("EC_EC"), null, engine("watch.liess.tv")))
        assertNull(manager.chooseEngineClientAlias(arrayOf("RSA"), null, engine("watch.liess.tv")))
    }

    @Test
    fun `normalizes host patterns like the Dart side`() {
        assertEquals("watch.liess.tv", normalizeCertificateHost(" Watch.Liess.TV. "))
        assertEquals("::1", normalizeCertificateHost("[::1]"))
        assertEquals("*.example.com", normalizeCertificateHostPattern("*.Example.com"))
        assertNull(normalizeCertificateHost("watch.liess.tv/feed"))
        assertNull(normalizeCertificateHost("user@watch.liess.tv"))
        assertNull(normalizeCertificateHost("a..b"))
        assertNull(normalizeCertificateHostPattern("*."))
        assertFalse(clientCertificateHostSelected(listOf("watch.liess.tv"), null))
    }

    @Test
    fun `extracts the common name from an escaped subject`() {
        assertEquals("phone, home", ClientIdentity.commonNameOf("CN=phone\\, home,O=Liess"))
        assertEquals("phone", ClientIdentity.commonNameOf("O=Liess,CN=phone"))
        assertNull(ClientIdentity.commonNameOf("O=Liess"))
    }

    @Test
    fun `builds a TLS socket factory with platform trust`() {
        val identity = ClientIdentity.fromPkcs12(fixture("client_legacy.p12"), password)
        val tls = ClientCertificateTls(identity, listOf("watch.liess.tv"))
        assertNotNull(tls.socketFactory)
        assertTrue(tls.trustManager.acceptedIssuers.isNotEmpty())
    }
}
