import 'dart:convert';
import 'dart:math';

import 'package:clipious/network/gateway_context.dart';
import 'package:clipious/network/watch_auth.dart';
import 'package:clipious/network/watch_auth_http_client.dart';
import 'package:clipious/settings/models/db/server.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';

const _issuer = 'https://sso.example';
const _clientId = 'videre-client';
const _server =
    Server(url: 'https://watch.example', id: 'account-1', profileId: 'default');
final _now = DateTime.utc(2026, 11, 13, 12);

String _jwt(Map<String, Object?> claims) {
  String part(Object value) =>
      base64Url.encode(utf8.encode(jsonEncode(value))).replaceAll('=', '');
  return '${part({'alg': 'RS256'})}.${part(claims)}.signature';
}

String _idToken(String id,
        {Duration lifetime = const Duration(hours: 1), String? nonce}) =>
    _jwt({
      'iss': _issuer,
      'aud': [_clientId, 'other'],
      'sub': 'user-1',
      'email': 'axl@example.test',
      'exp': _now.add(lifetime).millisecondsSinceEpoch ~/ 1000,
      'jti': id,
      if (nonce != null) 'nonce': nonce
    });

http.Response _json(Object value, [int status = 200]) =>
    http.Response(jsonEncode(value), status,
        headers: {'content-type': 'application/json'});

WatchAuthSession _session(String idToken,
        {String refreshToken = 'refresh-1', Duration? expiresIn}) =>
    WatchAuthSession(
        key: WatchAuth.accountKey(_server)!,
        origin: 'https://watch.example',
        header: 'X-Watch-Auth',
        issuer: _issuer,
        clientId: _clientId,
        tokenEndpoint: '$_issuer/oauth/v2/token',
        idToken: idToken,
        refreshToken: refreshToken,
        expiresAt: _now.add(expiresIn ?? const Duration(hours: 1)),
        email: 'axl@example.test');

/// Records token-endpoint traffic and answers refreshes from a queue.
class _Provider {
  final refreshes = <Map<String, String>>[];
  final responses = <http.Response>[];

  Future<http.Response> handle(http.Request request) async {
    if (request.url.toString() == '$_issuer/oauth/v2/token') {
      refreshes.add(request.bodyFields);
      return responses.removeAt(0);
    }
    return http.Response('not found', 404);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  late WatchAuth previous;

  setUp(() => previous = WatchAuth.instance);
  tearDown(() {
    WatchAuth.instance.dispose();
    WatchAuth.instance = previous;
  });

  WatchAuth install(_Provider provider,
      {WatchAuthStorage? storage, WatchAuthBrowser? browser}) {
    final auth = WatchAuth(
        storage: storage ?? MemoryWatchAuthStorage(),
        client: MockClient(provider.handle),
        now: () => _now,
        browser: browser,
        scheduleRefresh: false);
    WatchAuth.instance = auth;
    return auth;
  }

  group('PKCE', () {
    test('matches the RFC 7636 S256 example', () {
      final pkce = WatchAuthPkce.fromVerifier(
          'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk');
      expect(pkce.challenge, 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
      expect(WatchAuthPkce.method, 'S256');
    });

    test('creates unpadded URL-safe verifiers of valid length', () {
      final verifiers = {
        for (var i = 0; i < 20; i++) WatchAuthPkce.create(Random(i)).verifier
      };
      expect(verifiers, hasLength(20));
      for (final verifier in verifiers) {
        expect(verifier, matches(RegExp(r'^[A-Za-z0-9_-]{43,128}$')));
      }
    });
  });

  group('discovery', () {
    const contract = {
      'issuer': 'https://sso.example/',
      'client_id': _clientId,
      'scopes': 'openid email profile offline_access',
      'redirect_uri': 'videre-liess-oidc://callback',
      'header': 'X-Watch-Auth'
    };

    test('parses the server contract', () {
      final discovery = WatchAuthDiscovery.tryParse(contract)!;
      expect(discovery.issuer, _issuer);
      expect(discovery.clientId, _clientId);
      expect(discovery.scopes, 'openid email profile offline_access');
      expect(discovery.redirectUri.toString(), 'videre-liess-oidc://callback');
      expect(discovery.header, 'X-Watch-Auth');
    });

    test('rejects documents the app cannot use safely', () {
      for (final change in <Map<String, Object?>>[
        {'issuer': 'http://sso.example'},
        {'issuer': 'https://user@sso.example'},
        {'client_id': ''},
        {'client_id': 7},
        {'scopes': 'email profile'},
        {'redirect_uri': 'videre-auth://callback'},
        {'redirect_uri': 'https://watch.example/callback'},
        {'header': 'Authorization'},
        {'header': 'Cookie'},
        {'header': 'X-Videre-Gateway-Context'},
        {'header': 'X Watch'}
      ]) {
        expect(WatchAuthDiscovery.tryParse({...contract, ...change}), isNull,
            reason: '$change');
      }
      expect(WatchAuthDiscovery.tryParse('nope'), isNull);
      expect(WatchAuthDiscovery.tryParse(null), isNull);
    });

    test('a server without the document does not offer SSO', () async {
      final auth = WatchAuth(
          storage: MemoryWatchAuthStorage(),
          client: MockClient((request) async {
            expect(request.url.path, '/.well-known/watch-auth');
            return request.url.host == 'watch.example'
                ? _json(contract)
                : http.Response('missing', 404);
          }));
      expect(await auth.discover('https://watch.example'), isNotNull);
      expect(await auth.discover('https://plain.example'), isNull);
      expect(await auth.discover('http://watch.example'), isNull);
    });

    test('OpenID configuration must belong to the issuer', () {
      const config = {
        'issuer': _issuer,
        'authorization_endpoint': '$_issuer/oauth/v2/authorize',
        'token_endpoint': '$_issuer/oauth/v2/token'
      };
      expect(OidcConfiguration.parse(config, _issuer).tokenEndpoint.toString(),
          '$_issuer/oauth/v2/token');
      expect(() => OidcConfiguration.parse(config, 'https://other.example'),
          throwsA(isA<WatchAuthException>()));
      expect(
          () => OidcConfiguration.parse(
              {...config, 'token_endpoint': 'http://sso.example/token'},
              _issuer),
          throwsA(isA<WatchAuthException>()));
    });

    test('callback must carry this sign-in state and one code', () {
      final redirect = Uri.parse('videre-liess-oidc://callback');
      expect(
          WatchAuth.authorizationCode(
              Uri.parse('videre-liess-oidc://callback?code=abc&state=s1'),
              redirect,
              's1'),
          'abc');
      expect(
          WatchAuth.authorizationCode(
              Uri.parse(
                  'videre-liess-oidc://callback?error=access_denied&state=s1'),
              redirect,
              's1'),
          isNull);
      for (final callback in [
        'videre-liess-oidc://callback?code=abc&state=other',
        'videre-liess-oidc://callback?code=abc',
        'videre-liess-oidc://other?code=abc&state=s1',
        'videre-liess-auth://callback?code=abc&state=s1',
        'videre-liess-oidc://callback?code=a&code=b&state=s1',
        'videre-liess-oidc://callback?state=s1'
      ]) {
        expect(
            () => WatchAuth.authorizationCode(
                Uri.parse(callback), redirect, 's1'),
            throwsA(isA<WatchAuthException>()),
            reason: callback);
      }
    });
  });

  group('sign-in', () {
    test('runs authorization code with PKCE and stores the ID token', () async {
      Uri? opened;
      Map<String, String>? exchange;
      final auth = WatchAuth(
          storage: MemoryWatchAuthStorage(),
          now: () => _now,
          scheduleRefresh: false,
          client: MockClient((request) async {
            switch (request.url.toString()) {
              case 'https://watch.example/.well-known/watch-auth':
                return _json({
                  'issuer': _issuer,
                  'client_id': _clientId,
                  'scopes': 'openid email profile offline_access',
                  'redirect_uri': 'videre-liess-oidc://callback',
                  'header': 'X-Watch-Auth'
                });
              case '$_issuer/.well-known/openid-configuration':
                return _json({
                  'issuer': _issuer,
                  'authorization_endpoint': '$_issuer/oauth/v2/authorize',
                  'token_endpoint': '$_issuer/oauth/v2/token',
                  'revocation_endpoint': '$_issuer/oauth/v2/revoke'
                });
              case '$_issuer/oauth/v2/token':
                exchange = request.bodyFields;
                return _json({
                  'access_token': 'access',
                  'id_token': _idToken('first',
                      nonce: opened!.queryParameters['nonce']),
                  'refresh_token': 'refresh-1',
                  'expires_in': 3600
                });
            }
            return http.Response('unexpected', 500);
          }),
          browser: (url, scheme) async {
            opened = url;
            expect(scheme, 'videre-liess-oidc');
            return 'videre-liess-oidc://callback?code=the-code'
                '&state=${url.queryParameters['state']}';
          });
      WatchAuth.instance = auth;

      final session = await auth.signIn(_server);
      expect(session, isNotNull);
      final query = opened!.queryParameters;
      expect(opened!.path, '/oauth/v2/authorize');
      expect(query['response_type'], 'code');
      expect(query['client_id'], _clientId);
      expect(query['redirect_uri'], 'videre-liess-oidc://callback');
      expect(query['scope'], 'openid email profile offline_access');
      expect(query['code_challenge_method'], 'S256');
      expect(exchange!['grant_type'], 'authorization_code');
      expect(exchange!['code'], 'the-code');
      expect(exchange!['client_id'], _clientId);
      expect(exchange!.containsKey('client_secret'), isFalse);
      expect(WatchAuthPkce.fromVerifier(exchange!['code_verifier']!).challenge,
          query['code_challenge']);
      expect(session!.email, 'axl@example.test');
      expect(session.refreshToken, 'refresh-1');
      expect(session.expiresAt, _now.add(const Duration(hours: 1)));
      expect(_server.headersForUrl('https://watch.example/api/v1/stats'),
          containsPair('X-Watch-Auth', session.idToken));
    });

    test('an ID token for another client or nonce is refused', () async {
      final auth = WatchAuth(
          storage: MemoryWatchAuthStorage(),
          scheduleRefresh: false,
          client: MockClient((request) async {
            if (request.url.path == '/.well-known/openid-configuration') {
              return _json({
                'issuer': _issuer,
                'authorization_endpoint': '$_issuer/authorize',
                'token_endpoint': '$_issuer/oauth/v2/token'
              });
            }
            return _json({'id_token': _idToken('x', nonce: 'wrong')});
          }),
          browser: (url, _) async => 'videre-liess-oidc://callback?code=c'
              '&state=${url.queryParameters['state']}');
      await expectLater(
          auth.signIn(_server,
              discovery: WatchAuthDiscovery.tryParse(
                  {'issuer': _issuer, 'client_id': _clientId})),
          throwsA(isA<WatchAuthException>()));
      expect(auth.sessionFor(_server), isNull);
    });
  });

  group('refresh scheduling', () {
    test('refreshes five minutes before the ID token expires', () {
      final session = _session('a');
      expect(
          WatchAuth.refreshDelay(session, _now), const Duration(minutes: 55));
      expect(WatchAuth.needsRefresh(session, _now), isFalse);
      final later = _now.add(const Duration(minutes: 55));
      expect(WatchAuth.needsRefresh(session, later), isTrue);
      expect(WatchAuth.refreshDelay(session, later), Duration.zero);
      expect(
          WatchAuth.refreshDelay(session, _now.add(const Duration(hours: 2))),
          Duration.zero);
    });

    test('refresh rotates the refresh token and keeps it when not rotated',
        () async {
      final provider = _Provider()
        ..responses.addAll([
          _json({'id_token': _idToken('b'), 'refresh_token': 'refresh-2'}),
          _json({'id_token': _idToken('c')})
        ]);
      final auth = install(provider);
      await auth.store(_session('a', expiresIn: const Duration(minutes: 2)));
      final key = WatchAuth.accountKey(_server)!;

      final first = await auth.fresh(key);
      expect(first!.refreshToken, 'refresh-2');
      expect(provider.refreshes.single, {
        'grant_type': 'refresh_token',
        'refresh_token': 'refresh-1',
        'client_id': _clientId
      });
      final second = await auth.fresh(key, force: true);
      expect(second!.idToken, _idToken('c'));
      expect(second.refreshToken, 'refresh-2');
      expect(provider.refreshes.last['refresh_token'], 'refresh-2');
    });

    test('concurrent requests share one refresh', () async {
      final provider = _Provider()
        ..responses.add(_json({'id_token': _idToken('b')}));
      final auth = install(provider);
      await auth.store(_session('a', expiresIn: Duration.zero));
      final key = WatchAuth.accountKey(_server)!;
      final results = await Future.wait([auth.fresh(key), auth.fresh(key)]);
      expect(provider.refreshes, hasLength(1));
      expect(results.map((s) => s!.idToken).toSet(), {_idToken('b')});
    });

    test('a rejected refresh marks the account and does not retry', () async {
      final provider = _Provider()
        ..responses.add(_json({'error': 'invalid_grant'}, 400));
      final auth = install(provider);
      await auth.store(_session('a', expiresIn: Duration.zero));
      final key = WatchAuth.accountKey(_server)!;
      expect((await auth.fresh(key))!.needsSignIn, isTrue);
      expect((await auth.fresh(key, force: true))!.needsSignIn, isTrue);
      expect(provider.refreshes, hasLength(1));
      expect(_server.headersForUrl('https://watch.example/'),
          isNot(contains('X-Watch-Auth')));
    });

    test('a provider outage keeps the session for a later attempt', () async {
      final provider = _Provider()..responses.add(http.Response('busy', 503));
      final auth = install(provider);
      await auth.store(_session('a', expiresIn: Duration.zero));
      final session = await auth.fresh(WatchAuth.accountKey(_server)!);
      expect(session!.needsSignIn, isFalse);
      expect(session.idToken, 'a');
    });
  });

  group('header injection', () {
    test('only the account origin receives its token', () async {
      final auth = install(_Provider());
      await auth.store(_session('token-a'));
      expect(_server.headersForUrl('https://watch.example/vi/x/default.jpg'),
          containsPair('X-Watch-Auth', 'token-a'));
      expect(_server.headersForUrl('https://watch.example:8443/'), isNull);
      expect(auth.headersFor(_server, 'https://cdn.example/a'), isEmpty);
      expect(auth.headersFor(_server, 'http://watch.example/a'), isEmpty);
      // Another account on the same server has its own (absent) session.
      const other = Server(
          url: 'https://watch.example', id: 'account-2', profileId: 'default');
      expect(other.headersForUrl('https://watch.example/api/v1/stats'),
          isNot(contains('X-Watch-Auth')));
      // The Invidious token header is untouched.
      final withAuth = _server
          .copyWith(customHeaders: {'Authorization': 'Bearer invidious-token'});
      expect(withAuth.headersForUrl('https://watch.example/api/v1/feed'),
          containsPair('Authorization', 'Bearer invidious-token'));
    });

    test('the native header store receives every refreshed token', () async {
      const channel = MethodChannel('videre/watch_auth');
      final saved = <String, String>{};
      final calls = <String>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, (call) async {
        final arguments = call.arguments as Map?;
        calls.add(call.method);
        switch (call.method) {
          case 'save':
            saved[arguments!['key'] as String] = arguments['value'] as String;
            return null;
          case 'load':
            return saved[arguments!['key']];
          case 'loadAll':
            return saved;
        }
        return null;
      });
      addTearDown(() => TestDefaultBinaryMessengerBinding
          .instance.defaultBinaryMessenger
          .setMockMethodCallHandler(channel, null));
      final provider = _Provider()
        ..responses.add(
            _json({'id_token': _idToken('b'), 'refresh_token': 'refresh-2'}));
      final auth = install(provider,
          storage: const MethodChannelWatchAuthStorage(channel));
      await auth.store(_session('a', expiresIn: Duration.zero));
      final key = WatchAuth.accountKey(_server)!;

      await auth.fresh(key);
      final native = jsonDecode(saved[key]!) as Map<String, dynamic>;
      // Fields read by WatchAuthHeaders.publish() in the proxy plugin.
      expect(native['origin'], 'https://watch.example');
      expect(native['header'], 'X-Watch-Auth');
      expect(native['idToken'], _idToken('b'));
      expect(native['needsSignIn'], isFalse);
      expect(native['refreshToken'], 'refresh-2');
      expect(calls.where((c) => c == 'save'), hasLength(2));

      // A worker restarting from storage sees the refreshed session.
      final worker = WatchAuth(
          storage: const MethodChannelWatchAuthStorage(channel),
          scheduleRefresh: false);
      await worker.initialize();
      expect(worker.sessionFor(_server)!.idToken, _idToken('b'));
    });
  });

  group('API client', () {
    late List<http.BaseRequest> api;

    Future<http.Response> get(WatchAuthHttpClient client) => client
            .get(Uri.parse('https://watch.example/api/v1/auth/feed'), headers: {
          ..._server.headersForUrl('https://watch.example/api/v1/auth/feed')!,
          'Authorization': 'Bearer invidious-token'
        });

    WatchAuthHttpClient client(_Provider provider,
            http.Response Function(http.BaseRequest request) respond) =>
        WatchAuthHttpClient(MockClient((request) async {
          if (request.url.host == 'sso.example') {
            return provider.handle(request);
          }
          api.add(request);
          return respond(request);
        }));

    http.Response rejected() =>
        _json({'error': 'watch-auth token not accepted'}, 401);

    setUp(() => api = []);

    test('refreshes proactively before sending', () async {
      final provider = _Provider()
        ..responses.add(_json({'id_token': _idToken('b')}));
      final auth = install(provider);
      await auth.store(_session('a', expiresIn: const Duration(minutes: 4)));
      final response =
          await get(client(provider, (_) => http.Response('[]', 200)));
      expect(response.statusCode, 200);
      expect(provider.refreshes, hasLength(1));
      expect(api.single.headers['X-Watch-Auth'], _idToken('b'));
      expect(api.single.headers['Authorization'], 'Bearer invidious-token');
    });

    test('a rejected token is refreshed and the request replayed once',
        () async {
      final provider = _Provider()
        ..responses.add(_json({'id_token': _idToken('b')}));
      final auth = install(provider);
      await auth.store(_session('a'));
      final response = await get(client(
          provider,
          (request) => request.headers['X-Watch-Auth'] == 'a'
              ? rejected()
              : http.Response('[]', 200)));
      expect(response.statusCode, 200);
      expect(api.map((r) => r.headers['X-Watch-Auth']), ['a', _idToken('b')]);
      expect(provider.refreshes, hasLength(1));
    });

    test('a failed refresh returns the 401 and asks for sign-in', () async {
      final provider = _Provider()
        ..responses.add(_json({'error': 'invalid_grant'}, 400));
      final auth = install(provider);
      await auth.store(_session('a'));
      final rejecting = client(provider, (_) => rejected());
      final response = await get(rejecting);
      expect(response.statusCode, 401);
      expect(jsonDecode(response.body)['error'], contains('watch-auth'));
      expect(api, hasLength(1));
      expect(auth.sessionFor(_server)!.needsSignIn, isTrue);

      // No loop: later requests neither refresh nor send a stale token.
      await get(rejecting);
      expect(provider.refreshes, hasLength(1));
      expect(api.last.headers.containsKey('X-Watch-Auth'), isFalse);
    });

    test('a fresh token that is also refused stops retrying', () async {
      final provider = _Provider()
        ..responses.add(_json({'id_token': _idToken('b')}));
      final auth = install(provider);
      await auth.store(_session('a'));
      final response = await get(client(provider, (_) => rejected()));
      expect(response.statusCode, 401);
      expect(api, hasLength(2));
      expect(auth.sessionFor(_server)!.needsSignIn, isTrue);
    });

    test('an Invidious 401 is not treated as an SSO failure', () async {
      final provider = _Provider();
      final auth = install(provider);
      await auth.store(_session('a'));
      final response = await get(
          client(provider, (_) => _json({'error': 'Invalid signature'}, 401)));
      expect(response.statusCode, 401);
      expect(api, hasLength(1));
      expect(provider.refreshes, isEmpty);
      expect(auth.sessionFor(_server)!.needsSignIn, isFalse);
    });

    test('requests without the account context pass through', () async {
      final provider = _Provider();
      final auth = install(provider);
      await auth.store(_session('a'));
      final plain = client(provider, (_) => http.Response('ok', 200));
      await plain.get(Uri.parse('https://watch.example/api/v1/stats'));
      final marker = GatewayRequestContext.forAccount(
              'default', 'account-1', 'https://watch.example')!
          .encoded;
      await plain.get(Uri.parse('https://cdn.example/x'),
          headers: {gatewayContextHeader: marker});
      expect(api.map((r) => r.headers['X-Watch-Auth']), [null, null]);
    });
  });
}
