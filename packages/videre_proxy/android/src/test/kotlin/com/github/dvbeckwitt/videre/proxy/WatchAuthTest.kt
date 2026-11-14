package com.github.dvbeckwitt.videre.proxy

import java.util.concurrent.TimeUnit
import okhttp3.Call
import okhttp3.Connection
import okhttp3.HttpUrl
import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.ByteString.Companion.encodeUtf8
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class WatchAuthTest {
    private val key = "8c9502ae-b933-5fa1-a75d-c6d85c2ec021"
    private val marker = "v1.$key.${"https://watch.example".encodeUtf8().base64Url()}"
    private val context = GatewayContext.parse(marker)

    @After fun reset() {
        WatchAuthHeaders.clear()
        GatewayCookieAccessRegistry.provider = null
    }

    private fun send(request: Request): Request {
        GatewayCookieAccessRegistry.provider = DisabledSessions
        val chain = Chain(request)
        GatewayTransportInterceptor().intercept(chain).close()
        return chain.sent!!
    }

    @Test fun `account origin receives the newest token and replaces a stale source header`() {
        WatchAuthHeaders.put(key, "https://watch.example", "X-Watch-Auth", "first.token.value")
        val request = Request.Builder().url("https://watch.example/videoplayback?id=1")
            .header(GATEWAY_CONTEXT_HEADER, marker).header("X-Watch-Auth", "stale.token.value").build()
        assertEquals("first.token.value", send(request).header("X-Watch-Auth"))

        // A refresh in Flutter updates requests from sources created earlier.
        WatchAuthHeaders.publish(key, false, "https://watch.example", "X-Watch-Auth", "second.token.value")
        assertEquals("second.token.value", send(request).header("X-Watch-Auth"))
        assertNull(send(request).header(GATEWAY_CONTEXT_HEADER))
    }

    @Test fun `token never reaches another origin or port`() {
        WatchAuthHeaders.put(key, "https://watch.example", "X-Watch-Auth", "token")
        for (url in listOf("https://cdn.example/segment.ts", "https://watch.example:8443/api/v1/stats")) {
            val request = prepareGatewayRequest(Request.Builder().url(url).build(), context)
            assertNull(url, send(request).header("X-Watch-Auth"))
        }
    }

    @Test fun `sign-in required, invalid names and insecure origins publish no header`() {
        WatchAuthHeaders.put(key, "https://watch.example", "X-Watch-Auth", "token")
        WatchAuthHeaders.publish(key, true, "https://watch.example", "X-Watch-Auth", "token")
        assertNull(WatchAuthHeaders.current(key))
        for (name in listOf("Authorization", "Cookie", "X-Videre-Gateway-Context", "X Watch", "")) {
            WatchAuthHeaders.put(key, "https://watch.example", name, "token")
            assertNull(name, WatchAuthHeaders.current(key))
        }
        WatchAuthHeaders.put(key, "http://watch.example", "X-Watch-Auth", "token")
        assertNull(WatchAuthHeaders.current(key))
        WatchAuthHeaders.put(key, "https://watch.example", "X-Watch-Auth", "bad token\n")
        assertNull(WatchAuthHeaders.current(key))
        WatchAuthHeaders.put(key, "https://watch.example", "X-Watch-Auth", "secret-value")
        assertFalse(WatchAuthHeaders.current(key).toString().contains("secret-value"))
    }

    private object DisabledSessions : GatewayCookieAccess {
        override fun resolve(context: GatewayContext, url: HttpUrl) = GatewayCookies(false, false)
        override fun ingest(context: GatewayContext, url: HttpUrl, cookies: List<String>,
            statusCode: Int, contentType: String?, location: String?, revision: Long?) = false
    }

    private class Chain(private val original: Request) : Interceptor.Chain {
        var sent: Request? = null
        override fun request(): Request = original
        override fun proceed(request: Request): Response {
            sent = request
            return Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body("{}".toResponseBody()).build()
        }
        override fun connection(): Connection? = null
        override fun call(): Call = error("No socket is used by this boundary test.")
        override fun connectTimeoutMillis(): Int = 1000
        override fun readTimeoutMillis(): Int = 1000
        override fun writeTimeoutMillis(): Int = 1000
        override fun withConnectTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun withReadTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
        override fun withWriteTimeout(timeout: Int, unit: TimeUnit): Interceptor.Chain = this
    }
}
