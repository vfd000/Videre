package com.github.dvbeckwitt.videre.proxy

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.StandardMethodCodec
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Request
import org.json.JSONObject

internal const val WATCH_AUTH_PREFERENCES = "videre_watch_auth"

internal data class WatchAuthHeader(val origin: HttpUrl, val name: String, val token: String) {
    // Never print the ID token.
    override fun toString() = "WatchAuthHeader(origin=$origin, name=$name)"
}

/**
 * The current single sign-on ID token of each account, keyed by its non-secret
 * gateway context key. Flutter updates it after every refresh, so playback,
 * audio and worker requests created earlier still send the newest token.
 */
internal object WatchAuthHeaders {
    private val headers = ConcurrentHashMap<String, WatchAuthHeader>()
    private val namePattern = Regex("^[Xx]-[A-Za-z0-9-]{1,62}$")
    private val reserved = setOf(GATEWAY_CONTEXT_HEADER.lowercase(), NERDVPN_KEY_HEADER.lowercase())

    fun validName(name: String) = namePattern.matches(name) && name.lowercase() !in reserved

    private fun validToken(token: String) = token.isNotEmpty() && token.length <= 16384 &&
        token.all { it in '!'..'~' }

    fun put(key: String, origin: String, name: String, token: String) {
        val url = origin.toHttpUrlOrNull()
        if (url == null || !url.isHttps || url.username.isNotEmpty() || url.password.isNotEmpty() ||
            !validName(name) || !validToken(token)) {
            headers.remove(key)
            return
        }
        headers[key] = WatchAuthHeader(url, name, token)
    }

    fun remove(key: String) {
        headers.remove(key)
    }

    fun clear() = headers.clear()

    internal fun current(key: String): WatchAuthHeader? = headers[key]

    /** Only the account's own origin receives its token, including redirects. */
    fun apply(context: GatewayContext, url: HttpUrl, builder: Request.Builder) {
        val header = headers[context.key] ?: return
        if (!context.allows(url) || header.origin.scheme != url.scheme ||
            header.origin.host != url.host || header.origin.port != url.port) return
        builder.header(header.name, header.token)
    }

    fun publish(key: String, needsSignIn: Boolean, origin: String, name: String, token: String) {
        if (needsSignIn) remove(key) else put(key, origin, name, token)
    }

    /** The session JSON is written by Flutter's WatchAuthSession.toJson(). */
    fun publish(key: String, session: JSONObject) = publish(key, session.optBoolean("needsSignIn", false),
        session.optString("origin"), session.optString("header"), session.optString("idToken"))
}

/** Refresh and ID tokens are encrypted with an Android Keystore key. */
internal object WatchAuthStore {
    private const val KEY_ALIAS = "videre_watch_auth_v1"
    private val keyPattern = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    private var preferences: SharedPreferences? = null

    @Synchronized
    fun initialize(context: Context) {
        if (preferences != null) return
        val store = context.applicationContext.getSharedPreferences(WATCH_AUTH_PREFERENCES, Context.MODE_PRIVATE)
        preferences = store
        for (key in store.all.keys) {
            val session = read(store, key) ?: continue
            WatchAuthHeaders.publish(key, session)
        }
    }

    private fun secretKey(): SecretKey = synchronized(WatchAuthStore::class.java) {
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (keys.getKey(KEY_ALIAS, null) as? SecretKey) ?: KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).build())
        }.generateKey()
    }

    private fun store() = checkNotNull(preferences) { "Single sign-on storage is not initialized." }

    private fun read(store: SharedPreferences, key: String): JSONObject? {
        if (!keyPattern.matches(key)) return null
        val stored = store.getString(key, null) ?: return null
        return try {
            val bytes = Base64.decode(stored, Base64.NO_WRAP)
            require(bytes.size > 28 && bytes[0] == 1.toByte())
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, bytes.copyOfRange(1, 13)))
            cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
            JSONObject(String(cipher.doFinal(bytes.copyOfRange(13, bytes.size)), Charsets.UTF_8))
        } catch (_: Exception) {
            // A restored backup or reset Keystore cannot decrypt; sign in again.
            null
        }
    }

    @Synchronized
    fun load(key: String): String? = read(store(), key)?.toString()

    @Synchronized
    fun loadAll(): Map<String, String> {
        val store = store()
        return store.all.keys.mapNotNull { key -> read(store, key)?.let { key to it.toString() } }.toMap()
    }

    @Synchronized
    fun save(key: String, value: String) {
        require(keyPattern.matches(key)) { "Invalid account." }
        val session = JSONObject(value)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        cipher.updateAAD(key.toByteArray(Charsets.UTF_8))
        val encrypted = byteArrayOf(1) + cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        check(store().edit().putString(key, Base64.encodeToString(encrypted, Base64.NO_WRAP)).commit()) {
            "Single sign-on tokens could not be saved."
        }
        WatchAuthHeaders.publish(key, session)
    }

    @Synchronized
    fun clear(key: String) {
        store().edit().remove(key).commit()
        WatchAuthHeaders.remove(key)
    }

    /** One channel per Flutter engine (foreground, audio and workers). */
    fun attach(binding: FlutterPlugin.FlutterPluginBinding): MethodChannel =
        MethodChannel(binding.binaryMessenger, "videre/watch_auth",
            StandardMethodCodec.INSTANCE, binding.binaryMessenger.makeBackgroundTaskQueue()).also {
            it.setMethodCallHandler { call, result ->
                try {
                    when (call.method) {
                        "loadAll" -> result.success(loadAll())
                        "load" -> result.success(load(call.argument<String>("key") ?: ""))
                        "save" -> {
                            save(call.argument<String>("key") ?: "", call.argument<String>("value")
                                ?: throw IllegalArgumentException())
                            result.success(null)
                        }
                        "clear" -> {
                            clear(call.argument<String>("key") ?: "")
                            result.success(null)
                        }
                        else -> result.notImplemented()
                    }
                } catch (_: Exception) {
                    // Never include token material in a platform error.
                    result.error("WATCH_AUTH_UNAVAILABLE", "Single sign-on storage is unavailable.", null)
                }
            }
        }
}
