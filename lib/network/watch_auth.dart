import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_web_auth_2/flutter_web_auth_2.dart';
import 'package:http/http.dart' as http;
import 'package:logging/logging.dart';

import '../settings/models/db/server.dart';
import 'gateway_context.dart';

/// Custom URL scheme that receives the single sign-on authorization response.
/// Upstream Videre installs side by side, so this fork uses its own scheme.
const watchAuthCallbackScheme = 'videre-liess-oidc';
const watchAuthDefaultHeader = 'X-Watch-Auth';
const watchAuthDiscoveryPath = '/.well-known/watch-auth';

/// Refresh the ID token this long before its `exp` claim.
const watchAuthRefreshMargin = Duration(minutes: 5);

final _log = Logger('WatchAuth');

class WatchAuthException implements Exception {
  final String message;
  const WatchAuthException(this.message);

  @override
  String toString() => message;
}

final _headerName = RegExp(r'^[Xx]-[A-Za-z0-9-]{1,62}$');
const _reservedHeaders = {'x-videre-gateway-context', 'x-invidious-token'};

bool isValidWatchAuthHeader(String name) =>
    _headerName.hasMatch(name) &&
    !_reservedHeaders.contains(name.toLowerCase());

bool _isHttpsUrl(Uri? uri) =>
    uri != null &&
    uri.scheme == 'https' &&
    uri.host.isNotEmpty &&
    uri.userInfo.isEmpty &&
    !uri.hasFragment;

/// The server's `/.well-known/watch-auth` document.
@immutable
class WatchAuthDiscovery {
  final String issuer;
  final String clientId;
  final String scopes;
  final Uri redirectUri;
  final String header;

  const WatchAuthDiscovery(
      {required this.issuer,
      required this.clientId,
      required this.scopes,
      required this.redirectUri,
      required this.header});

  /// Returns null for anything the app cannot safely use.
  static WatchAuthDiscovery? tryParse(Object? json) {
    if (json is! Map) return null;
    final issuer = json['issuer'];
    final clientId = json['client_id'];
    final scopes = json['scopes'] ?? 'openid email profile offline_access';
    final redirect =
        json['redirect_uri'] ?? '$watchAuthCallbackScheme://callback';
    final header = json['header'] ?? watchAuthDefaultHeader;
    if (issuer is! String ||
        clientId is! String ||
        scopes is! String ||
        redirect is! String ||
        header is! String) {
      return null;
    }
    final issuerUri = Uri.tryParse(issuer);
    if (!_isHttpsUrl(issuerUri) || issuerUri!.hasQuery) return null;
    if (clientId.isEmpty ||
        clientId.length > 256 ||
        clientId.contains(RegExp(r'\s'))) {
      return null;
    }
    final scopeList = scopes.split(' ').where((s) => s.isNotEmpty).toList();
    if (!scopeList.contains('openid') || scopes.length > 1024) return null;
    final redirectUri = Uri.tryParse(redirect);
    // The app can only receive its own registered callback scheme.
    if (redirectUri == null ||
        redirectUri.scheme != watchAuthCallbackScheme ||
        redirectUri.host.isEmpty ||
        redirectUri.hasQuery ||
        redirectUri.hasFragment) {
      return null;
    }
    if (!isValidWatchAuthHeader(header)) return null;
    return WatchAuthDiscovery(
        issuer: issuer.endsWith('/')
            ? issuer.substring(0, issuer.length - 1)
            : issuer,
        clientId: clientId,
        scopes: scopeList.join(' '),
        redirectUri: redirectUri,
        header: header);
  }
}

/// The parts of the issuer's OpenID configuration used by a public client.
@immutable
class OidcConfiguration {
  final Uri authorizationEndpoint;
  final Uri tokenEndpoint;
  final Uri? revocationEndpoint;

  const OidcConfiguration(
      {required this.authorizationEndpoint,
      required this.tokenEndpoint,
      this.revocationEndpoint});

  static OidcConfiguration parse(Object? json, String expectedIssuer) {
    if (json is! Map) {
      throw const WatchAuthException('The sign-in provider is unavailable.');
    }
    String strip(String value) =>
        value.endsWith('/') ? value.substring(0, value.length - 1) : value;
    final issuer = json['issuer'];
    if (issuer is! String || strip(issuer) != strip(expectedIssuer)) {
      throw const WatchAuthException(
          'The sign-in provider does not match this server.');
    }
    Uri? endpoint(String name) {
      final value = json[name];
      final uri = value is String ? Uri.tryParse(value) : null;
      return _isHttpsUrl(uri) ? uri : null;
    }

    final authorization = endpoint('authorization_endpoint');
    final token = endpoint('token_endpoint');
    if (authorization == null || token == null) {
      throw const WatchAuthException('The sign-in provider is unavailable.');
    }
    return OidcConfiguration(
        authorizationEndpoint: authorization,
        tokenEndpoint: token,
        revocationEndpoint: endpoint('revocation_endpoint'));
  }
}

/// RFC 7636 proof key, S256 only.
@immutable
class WatchAuthPkce {
  final String verifier;
  final String challenge;

  WatchAuthPkce.fromVerifier(this.verifier)
      : challenge =
            base64UrlNoPadding(sha256.convert(ascii.encode(verifier)).bytes);

  factory WatchAuthPkce.create([Random? random]) =>
      WatchAuthPkce.fromVerifier(randomUrlSafe(32, random));

  static const method = 'S256';
}

String base64UrlNoPadding(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

String randomUrlSafe(int bytes, [Random? random]) {
  final source = random ?? Random.secure();
  return base64UrlNoPadding(
      List<int>.generate(bytes, (_) => source.nextInt(256)));
}

/// Reads (does not verify) JWT claims. The ID token comes straight from the
/// issuer's token endpoint over TLS; the server validates its signature.
Map<String, dynamic>? decodeJwtClaims(String token) {
  final parts = token.split('.');
  if (parts.length != 3) return null;
  try {
    final value = jsonDecode(
        utf8.decode(base64Url.decode(base64Url.normalize(parts[1]))));
    return value is Map<String, dynamic> ? value : null;
  } catch (_) {
    return null;
  }
}

@immutable
class WatchAuthSession {
  /// Gateway context key of the account (profile, account and origin).
  final String key;
  final String origin;
  final String header;
  final String issuer;
  final String clientId;
  final String tokenEndpoint;
  final String? revocationEndpoint;
  final String idToken;
  final String? refreshToken;
  final DateTime expiresAt;
  final String? email;
  final bool needsSignIn;

  const WatchAuthSession(
      {required this.key,
      required this.origin,
      required this.header,
      required this.issuer,
      required this.clientId,
      required this.tokenEndpoint,
      this.revocationEndpoint,
      required this.idToken,
      this.refreshToken,
      required this.expiresAt,
      this.email,
      this.needsSignIn = false});

  WatchAuthSession copyWith(
          {String? idToken,
          String? refreshToken,
          DateTime? expiresAt,
          String? email,
          bool? needsSignIn}) =>
      WatchAuthSession(
          key: key,
          origin: origin,
          header: header,
          issuer: issuer,
          clientId: clientId,
          tokenEndpoint: tokenEndpoint,
          revocationEndpoint: revocationEndpoint,
          idToken: idToken ?? this.idToken,
          refreshToken: refreshToken ?? this.refreshToken,
          expiresAt: expiresAt ?? this.expiresAt,
          email: email ?? this.email,
          needsSignIn: needsSignIn ?? this.needsSignIn);

  /// Field names are also read by the native header store (WatchAuth.kt).
  Map<String, dynamic> toJson() => {
        'origin': origin,
        'header': header,
        'issuer': issuer,
        'clientId': clientId,
        'tokenEndpoint': tokenEndpoint,
        if (revocationEndpoint != null)
          'revocationEndpoint': revocationEndpoint,
        'idToken': idToken,
        if (refreshToken != null) 'refreshToken': refreshToken,
        'expiresAt': expiresAt.millisecondsSinceEpoch,
        if (email != null) 'email': email,
        'needsSignIn': needsSignIn
      };

  static WatchAuthSession? tryFromJson(String key, Object? json) {
    if (json is! Map) return null;
    final origin = json['origin'];
    final header = json['header'];
    final issuer = json['issuer'];
    final clientId = json['clientId'];
    final tokenEndpoint = json['tokenEndpoint'];
    final idToken = json['idToken'];
    final expiresAt = json['expiresAt'];
    if (origin is! String ||
        header is! String ||
        !isValidWatchAuthHeader(header) ||
        issuer is! String ||
        clientId is! String ||
        tokenEndpoint is! String ||
        idToken is! String ||
        expiresAt is! int) {
      return null;
    }
    final revocation = json['revocationEndpoint'];
    final refresh = json['refreshToken'];
    final email = json['email'];
    return WatchAuthSession(
        key: key,
        origin: origin,
        header: header,
        issuer: issuer,
        clientId: clientId,
        tokenEndpoint: tokenEndpoint,
        revocationEndpoint: revocation is String ? revocation : null,
        idToken: idToken,
        refreshToken: refresh is String && refresh.isNotEmpty ? refresh : null,
        expiresAt: DateTime.fromMillisecondsSinceEpoch(expiresAt, isUtc: true),
        email: email is String ? email : null,
        needsSignIn: json['needsSignIn'] == true);
  }

  @override
  String toString() => 'WatchAuthSession(origin: $origin, '
      'expiresAt: $expiresAt, needsSignIn: $needsSignIn)';
}

/// Durable, encrypted token storage. Android keeps it in the native proxy
/// plugin, which also injects the header into native playback requests.
abstract class WatchAuthStorage {
  Future<Map<String, String>> loadAll();
  Future<String?> load(String key);
  Future<void> save(String key, String value);
  Future<void> clear(String key);
}

class MethodChannelWatchAuthStorage implements WatchAuthStorage {
  final MethodChannel _channel;
  const MethodChannelWatchAuthStorage(
      [this._channel = const MethodChannel('videre/watch_auth')]);

  @override
  Future<Map<String, String>> loadAll() async =>
      (await _channel.invokeMapMethod<String, String>('loadAll')) ?? {};

  @override
  Future<String?> load(String key) =>
      _channel.invokeMethod<String>('load', {'key': key});

  @override
  Future<void> save(String key, String value) =>
      _channel.invokeMethod<void>('save', {'key': key, 'value': value});

  @override
  Future<void> clear(String key) =>
      _channel.invokeMethod<void>('clear', {'key': key});
}

class MemoryWatchAuthStorage implements WatchAuthStorage {
  final values = <String, String>{};

  @override
  Future<Map<String, String>> loadAll() async => Map.of(values);

  @override
  Future<String?> load(String key) async => values[key];

  @override
  Future<void> save(String key, String value) async {
    values[key] = value;
  }

  @override
  Future<void> clear(String key) async {
    values.remove(key);
  }
}

typedef WatchAuthBrowser = Future<String> Function(
    Uri authorizationUrl, String callbackScheme);

Future<String> _defaultBrowser(Uri url, String scheme) =>
    // Chrome Custom Tabs: Zitadel's login needs JavaScript and keeps its own
    // browser session, which the later Invidious token sign-in reuses.
    FlutterWebAuth2.authenticate(
        url: url.toString(), callbackUrlScheme: scheme);

enum _RefreshResult { refreshed, rejected, unavailable }

/// Per-account OIDC sessions for servers that publish `/.well-known/watch-auth`.
class WatchAuth {
  WatchAuth(
      {WatchAuthStorage? storage,
      http.Client? client,
      DateTime Function()? now,
      WatchAuthBrowser? browser,
      this.scheduleRefresh = true})
      : _storage = storage ??
            (!kIsWeb && Platform.isAndroid
                ? const MethodChannelWatchAuthStorage()
                : MemoryWatchAuthStorage()),
        _client = client,
        _now = now ?? DateTime.now,
        _browser = browser ?? _defaultBrowser;

  static WatchAuth instance = WatchAuth();

  final WatchAuthStorage _storage;
  http.Client? _client;
  final DateTime Function() _now;
  final WatchAuthBrowser _browser;
  bool scheduleRefresh;
  final _sessions = <String, WatchAuthSession>{};
  final _refreshing = <String, Future<WatchAuthSession?>>{};
  final _timers = <String, Timer>{};

  /// Increments whenever any session changes, for settings UI.
  final revision = ValueNotifier<int>(0);

  http.Client get _http => _client ??= http.Client();

  /// Loads saved sessions. Workers pass their native transport.
  Future<void> initialize({http.Client? client, bool? scheduleRefresh}) async {
    if (client != null) _client = client;
    if (scheduleRefresh != null) this.scheduleRefresh = scheduleRefresh;
    try {
      final saved = await _storage.loadAll();
      for (final entry in saved.entries) {
        final session = _decode(entry.key, entry.value);
        if (session != null) _put(session);
      }
    } catch (error) {
      _log.severe('Saved single sign-on sessions are unavailable '
          '(${error.runtimeType}).');
    }
  }

  static String? accountKey(Server server) => GatewayRequestContext.forAccount(
          server.profileId, server.accountId, server.url)
      ?.key;

  WatchAuthSession? sessionFor(Server server) {
    final key = accountKey(server);
    return key == null ? null : _sessions[key];
  }

  /// Synchronous header for media, image and download requests.
  Map<String, String> headersFor(Server server, String targetUrl) {
    final session = sessionFor(server);
    final target = Uri.tryParse(targetUrl);
    if (session == null ||
        session.needsSignIn ||
        target == null ||
        target.scheme != 'https' ||
        target.host.isEmpty ||
        target.userInfo.isNotEmpty ||
        target.origin != session.origin) {
      return const {};
    }
    return {session.header: session.idToken};
  }

  /// Session addressed by a request's internal gateway context marker.
  WatchAuthSession? sessionForContext(String? marker, Uri target) {
    if (marker == null) return null;
    final context = GatewayRequestContext.tryParse(marker);
    if (context == null || !context.allows(target)) return null;
    final session = _sessions[context.key];
    return session != null && session.origin == target.origin ? session : null;
  }

  WatchAuthSession? _decode(String key, String value) {
    try {
      return WatchAuthSession.tryFromJson(key, jsonDecode(value));
    } on FormatException {
      return null;
    }
  }

  void _put(WatchAuthSession session) {
    _sessions[session.key] = session;
    _schedule(session);
    revision.value++;
  }

  Future<void> _save(WatchAuthSession session) async {
    await _storage.save(session.key, jsonEncode(session.toJson()));
    _put(session);
  }

  @visibleForTesting
  Future<void> store(WatchAuthSession session) => _save(session);

  static bool needsRefresh(WatchAuthSession session, DateTime now) =>
      !now.isBefore(session.expiresAt.subtract(watchAuthRefreshMargin));

  static Duration refreshDelay(WatchAuthSession session, DateTime now) {
    final delay =
        session.expiresAt.subtract(watchAuthRefreshMargin).difference(now);
    return delay.isNegative ? Duration.zero : delay;
  }

  void _schedule(WatchAuthSession session, {Duration? after}) {
    _timers.remove(session.key)?.cancel();
    if (!scheduleRefresh ||
        session.needsSignIn ||
        session.refreshToken == null) {
      return;
    }
    _timers[session.key] =
        Timer(after ?? refreshDelay(session, _now()), () async {
      _timers.remove(session.key);
      final current = _sessions[session.key];
      if (current == null || current.needsSignIn) return;
      final result = await fresh(session.key);
      // A transient failure retries later; a rejection stops (no loop).
      if (result != null &&
          !result.needsSignIn &&
          needsRefresh(result, _now())) {
        _schedule(result, after: const Duration(minutes: 1));
      }
    });
  }

  /// Returns a usable session, refreshing it first when it is about to expire
  /// or when [force] is set (the server rejected [rejectedToken]).
  Future<WatchAuthSession?> fresh(String key,
      {bool force = false, String? rejectedToken}) {
    final current = _sessions[key];
    if (current == null) return Future.value(null);
    if (current.needsSignIn) return Future.value(current);
    if (!needsRefresh(current, _now()) &&
        (!force ||
            (rejectedToken != null && current.idToken != rejectedToken))) {
      return Future.value(current);
    }
    // A block body: returning the removed future would make it wait on itself.
    return _refreshing[key] ??= _refresh(key).whenComplete(() {
      _refreshing.remove(key);
    });
  }

  Future<WatchAuthSession?> _refresh(String key) async {
    var session = _sessions[key]!;
    // Another engine (a worker) may already have rotated the tokens.
    final stored = await _reload(key);
    if (stored == null) return null;
    if (stored.idToken != session.idToken &&
        !stored.needsSignIn &&
        !needsRefresh(stored, _now())) {
      return stored;
    }
    session = stored;
    var result = await _refreshWith(session);
    if (result.$1 == _RefreshResult.rejected) {
      // A rotated refresh token saved by another engine wins a race.
      final latest = await _reload(key);
      if (latest != null && latest.refreshToken != session.refreshToken) {
        if (!latest.needsSignIn && !needsRefresh(latest, _now())) {
          return latest;
        }
        session = latest;
        result = await _refreshWith(session);
      }
    }
    switch (result.$1) {
      case _RefreshResult.refreshed:
        await _save(result.$2!);
        return result.$2;
      case _RefreshResult.rejected:
        return markSignInRequired(key);
      case _RefreshResult.unavailable:
        return _sessions[key];
    }
  }

  Future<WatchAuthSession?> _reload(String key) async {
    try {
      final value = await _storage.load(key);
      final session = value == null ? null : _decode(key, value);
      if (session == null) {
        _sessions.remove(key);
        _timers.remove(key)?.cancel();
        revision.value++;
        return null;
      }
      if (session.idToken != _sessions[key]?.idToken ||
          session.needsSignIn != _sessions[key]?.needsSignIn) {
        _put(session);
      }
      return session;
    } catch (_) {
      return _sessions[key];
    }
  }

  Future<(_RefreshResult, WatchAuthSession?)> _refreshWith(
      WatchAuthSession session) async {
    final refreshToken = session.refreshToken;
    if (refreshToken == null || session.needsSignIn) {
      return (_RefreshResult.rejected, null);
    }
    final http.Response response;
    try {
      response = await _http.post(Uri.parse(session.tokenEndpoint), headers: {
        'Accept': 'application/json'
      }, body: {
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
        'client_id': session.clientId
      }).timeout(const Duration(seconds: 30));
    } catch (error) {
      _log.info(
          'Single sign-on refresh is unavailable (${error.runtimeType}).');
      return (_RefreshResult.unavailable, null);
    }
    if (response.statusCode >= 500 || response.statusCode == 429) {
      return (_RefreshResult.unavailable, null);
    }
    if (response.statusCode != 200) {
      _log.info('Single sign-on refresh was rejected '
          '(HTTP ${response.statusCode}).');
      return (_RefreshResult.rejected, null);
    }
    try {
      final tokens = _parseTokens(response, session.issuer, session.clientId);
      return (
        _RefreshResult.refreshed,
        session.copyWith(
            idToken: tokens.idToken,
            // Keep the old refresh token unless the provider rotated it.
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt,
            email: tokens.email,
            needsSignIn: false)
      );
    } on WatchAuthException {
      return (_RefreshResult.rejected, null);
    }
  }

  Future<WatchAuthSession?> markSignInRequired(String key) async {
    final current = _sessions[key];
    if (current == null) return null;
    final updated = current.copyWith(needsSignIn: true);
    try {
      await _save(updated);
    } catch (_) {
      _put(updated);
    }
    return updated;
  }

  /// Fetches `<server>/.well-known/watch-auth`; null when SSO is not offered.
  Future<WatchAuthDiscovery?> discover(String serverUrl,
      {Map<String, String>? headers}) async {
    final server = Uri.tryParse(serverUrl);
    if (!_isHttpsUrl(server)) return null;
    try {
      final response = await _http
          .get(Uri.parse('${server!.origin}$watchAuthDiscoveryPath'), headers: {
        ...?headers,
        'Accept': 'application/json'
      }).timeout(const Duration(seconds: 10));
      if (response.statusCode != 200) return null;
      return WatchAuthDiscovery.tryParse(
          jsonDecode(utf8.decode(response.bodyBytes)));
    } catch (_) {
      return null;
    }
  }

  Future<OidcConfiguration> _configuration(String issuer) async {
    final http.Response response;
    try {
      response = await _http
          .get(Uri.parse('$issuer/.well-known/openid-configuration'), headers: {
        'Accept': 'application/json'
      }).timeout(const Duration(seconds: 15));
    } catch (_) {
      throw const WatchAuthException(
          'The sign-in provider could not be reached.');
    }
    if (response.statusCode != 200) {
      throw const WatchAuthException('The sign-in provider is unavailable.');
    }
    try {
      return OidcConfiguration.parse(
          jsonDecode(utf8.decode(response.bodyBytes)), issuer);
    } on FormatException {
      throw const WatchAuthException('The sign-in provider is unavailable.');
    }
  }

  /// Runs Authorization Code + PKCE in a Custom Tab. Returns null if the user
  /// cancels. [server] may be an account that is not saved yet.
  Future<WatchAuthSession?> signIn(Server server,
      {WatchAuthDiscovery? discovery}) async {
    final key = accountKey(server);
    final origin = Uri.tryParse(server.url);
    if (key == null || !_isHttpsUrl(origin)) {
      throw const WatchAuthException(
          'Single sign-on requires an HTTPS server address.');
    }
    final sso =
        discovery ?? await discover(server.url, headers: server.customHeaders);
    if (sso == null) {
      throw const WatchAuthException(
          'This server does not offer single sign-on.');
    }
    final config = await _configuration(sso.issuer);
    final pkce = WatchAuthPkce.create();
    final state = randomUrlSafe(24);
    final nonce = randomUrlSafe(24);
    final authorize = config.authorizationEndpoint.replace(queryParameters: {
      ...config.authorizationEndpoint.queryParameters,
      'response_type': 'code',
      'client_id': sso.clientId,
      'redirect_uri': sso.redirectUri.toString(),
      'scope': sso.scopes,
      'state': state,
      'nonce': nonce,
      'code_challenge': pkce.challenge,
      'code_challenge_method': WatchAuthPkce.method
    });
    final String result;
    try {
      result = await _browser(authorize, sso.redirectUri.scheme);
    } on PlatformException catch (error) {
      if (error.code == 'CANCELED') return null;
      rethrow;
    }
    final code = authorizationCode(Uri.parse(result), sso.redirectUri, state);
    if (code == null) return null;

    final http.Response response;
    try {
      response = await _http.post(config.tokenEndpoint, headers: {
        'Accept': 'application/json'
      }, body: {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': sso.redirectUri.toString(),
        'client_id': sso.clientId,
        'code_verifier': pkce.verifier
      }).timeout(const Duration(seconds: 30));
    } catch (_) {
      throw const WatchAuthException(
          'Sign-in could not be completed. Check your connection and try again.');
    }
    if (response.statusCode != 200) {
      _log.info('Single sign-on code exchange failed '
          '(HTTP ${response.statusCode}).');
      throw const WatchAuthException(
          'The sign-in provider did not accept this sign-in. Try again.');
    }
    final tokens =
        _parseTokens(response, sso.issuer, sso.clientId, nonce: nonce);
    final session = WatchAuthSession(
        key: key,
        origin: origin!.origin,
        header: sso.header,
        issuer: sso.issuer,
        clientId: sso.clientId,
        tokenEndpoint: config.tokenEndpoint.toString(),
        revocationEndpoint: config.revocationEndpoint?.toString(),
        idToken: tokens.idToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt,
        email: tokens.email);
    await _save(session);
    return session;
  }

  /// Validates the callback and returns its code; null for a user denial.
  @visibleForTesting
  static String? authorizationCode(
      Uri callback, Uri redirectUri, String expectedState) {
    if (callback.scheme != redirectUri.scheme ||
        callback.host != redirectUri.host ||
        callback.path != redirectUri.path ||
        callback.userInfo.isNotEmpty ||
        callback.hasPort ||
        callback.queryParametersAll['state']?.length != 1 ||
        callback.queryParameters['state'] != expectedState) {
      throw const WatchAuthException(
          'Sign-in returned an unexpected callback.');
    }
    final error = callback.queryParameters['error'];
    if (error != null) {
      if (error == 'access_denied') return null;
      throw const WatchAuthException('The sign-in provider reported an error.');
    }
    final code = callback.queryParameters['code'];
    if (code == null ||
        code.isEmpty ||
        code.length > 4096 ||
        callback.queryParametersAll['code']?.length != 1) {
      throw const WatchAuthException('Sign-in did not return a code.');
    }
    return code;
  }

  static ({
    String idToken,
    String? refreshToken,
    DateTime expiresAt,
    String? email
  }) _parseTokens(http.Response response, String issuer, String clientId,
      {String? nonce}) {
    Object? json;
    try {
      json = jsonDecode(utf8.decode(response.bodyBytes));
    } on FormatException {
      json = null;
    }
    final idToken = json is Map ? json['id_token'] : null;
    if (idToken is! String || idToken.isEmpty || idToken.length > 16384) {
      throw const WatchAuthException(
          'The sign-in provider did not return an ID token.');
    }
    final claims = decodeJwtClaims(idToken);
    final exp = claims?['exp'];
    final aud = claims?['aud'];
    final iss = claims?['iss'];
    String strip(String value) =>
        value.endsWith('/') ? value.substring(0, value.length - 1) : value;
    if (claims == null ||
        exp is! num ||
        iss is! String ||
        strip(iss) != strip(issuer) ||
        !(aud == clientId || (aud is List && aud.contains(clientId))) ||
        (nonce != null && claims['nonce'] != nonce)) {
      throw const WatchAuthException(
          'The sign-in provider returned an invalid ID token.');
    }
    final refresh = (json as Map)['refresh_token'];
    final email = claims['email'];
    return (
      idToken: idToken,
      refreshToken: refresh is String && refresh.isNotEmpty ? refresh : null,
      expiresAt: DateTime.fromMillisecondsSinceEpoch((exp * 1000).toInt(),
          isUtc: true),
      email: email is String
          ? email
          : (claims['preferred_username'] is String
              ? claims['preferred_username'] as String
              : null)
    );
  }

  /// Forgets the account's tokens and revokes its refresh token (best effort).
  Future<void> signOut(Server server) async {
    final key = accountKey(server);
    if (key == null) return;
    final session = _sessions.remove(key);
    _timers.remove(key)?.cancel();
    _refreshing.remove(key);
    await _storage.clear(key);
    revision.value++;
    final revocation = session?.revocationEndpoint;
    final refreshToken = session?.refreshToken;
    if (revocation != null && refreshToken != null) {
      unawaited(_http
          .post(Uri.parse(revocation), body: {
            'token': refreshToken,
            'token_type_hint': 'refresh_token',
            'client_id': session!.clientId
          })
          .timeout(const Duration(seconds: 15))
          .then<void>((_) {}, onError: (Object _) {}));
    }
  }

  @visibleForTesting
  void dispose() {
    for (final timer in _timers.values) {
      timer.cancel();
    }
    _timers.clear();
  }
}
