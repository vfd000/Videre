import 'dart:convert';

import 'package:http/http.dart' as http;

import 'gateway_context.dart';
import 'watch_auth.dart';

/// Adds the account's single sign-on ID token to API requests on its origin.
/// The token is refreshed shortly before it expires; a request the server
/// rejects with 401 is refreshed and replayed once.
class WatchAuthHttpClient extends http.BaseClient {
  final http.Client _inner;
  final WatchAuth? _auth;

  WatchAuthHttpClient(this._inner, {WatchAuth? auth}) : _auth = auth;

  WatchAuth get _watchAuth => _auth ?? WatchAuth.instance;

  static const _maxRejectionBody = 8192;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final auth = _watchAuth;
    final session = auth.sessionForContext(
        request.headers[gatewayContextHeader], request.url);
    if (session == null) return _inner.send(request);

    final current = await auth.fresh(session.key) ?? session;
    final token = current.needsSignIn ? null : current.idToken;
    if (request is! http.Request) {
      // Streamed bodies cannot be replayed; send once with the newest token.
      return _inner.send(_withToken(request, current.header, token));
    }
    final response = await _inner.send(_copy(request, current.header, token));
    if (response.statusCode != 401 || token == null) return response;

    final rejected = await _rejection(response);
    if (!rejected.$1) return rejected.$2;
    final refreshed =
        await auth.fresh(session.key, force: true, rejectedToken: token);
    if (refreshed == null ||
        refreshed.needsSignIn ||
        refreshed.idToken == token) {
      return rejected.$2;
    }
    final retry =
        await _inner.send(_copy(request, refreshed.header, refreshed.idToken));
    if (retry.statusCode != 401) return retry;
    final again = await _rejection(retry);
    // A brand-new token was also refused: stop and ask the user to sign in.
    if (again.$1) await auth.markSignInRequired(session.key);
    return again.$2;
  }

  static http.BaseRequest _withToken(
      http.BaseRequest request, String header, String? token) {
    request.headers.remove(header);
    if (token != null) request.headers[header] = token;
    return request;
  }

  static http.Request _copy(
      http.Request request, String header, String? token) {
    final copy = http.Request(request.method, request.url)
      ..followRedirects = request.followRedirects
      ..maxRedirects = request.maxRedirects
      ..persistentConnection = request.persistentConnection
      ..headers.addAll(request.headers)
      ..bodyBytes = request.bodyBytes;
    return _withToken(copy, header, token) as http.Request;
  }

  /// Reads a 401 body and reports whether it is the watch-auth rejection.
  static Future<(bool, http.StreamedResponse)> _rejection(
      http.StreamedResponse response) async {
    final bytes = await response.stream.toBytes();
    final rebuilt = http.StreamedResponse(
        Stream.value(bytes), response.statusCode,
        contentLength: bytes.length,
        request: response.request,
        headers: response.headers,
        isRedirect: response.isRedirect,
        persistentConnection: response.persistentConnection,
        reasonPhrase: response.reasonPhrase);
    return (isWatchAuthRejection(bytes), rebuilt);
  }

  static bool isWatchAuthRejection(List<int> body) {
    if (body.length > _maxRejectionBody) return false;
    try {
      final json = jsonDecode(utf8.decode(body));
      final error = json is Map ? json['error'] : null;
      return error is String && error.toLowerCase().contains('watch-auth');
    } catch (_) {
      return false;
    }
  }

  @override
  void close() => _inner.close();
}
