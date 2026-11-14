import 'dart:io';

/// dart:io binds a SecurityContext to a whole HttpClient, so a client
/// certificate cannot be limited to some hosts within one client. This wrapper
/// keeps two clients and picks one per request: the certificate-bearing client
/// for selected hosts, the plain one for every other host.
///
/// Redirects that dart:io follows internally stay on the client that opened
/// the request. The API client follows redirects itself, so each hop is routed
/// again here.
class ClientCertificateRoutingHttpClient implements HttpClient {
  final HttpClient Function() _createPlain;
  final HttpClient Function() _createWithCertificate;
  final bool Function(String host) _presentsTo;
  final _settings = <Object, void Function(HttpClient)>{};
  HttpClient? _plain;
  HttpClient? _withCertificate;
  bool _closed = false;

  ClientCertificateRoutingHttpClient({
    required HttpClient Function() plain,
    required HttpClient Function() withCertificate,
    required bool Function(String host) presentsTo,
  })  : _createPlain = plain,
        _createWithCertificate = withCertificate,
        _presentsTo = presentsTo;

  HttpClient _create(HttpClient Function() factory) {
    final client = factory();
    try {
      for (final setting in _settings.values) {
        setting(client);
      }
      return client;
    } catch (_) {
      client.close(force: true);
      rethrow;
    }
  }

  HttpClient _clientFor(String host) {
    if (_closed) throw StateError('HttpClient is closed');
    return _presentsTo(host)
        ? _withCertificate ??= _create(_createWithCertificate)
        : _plain ??= _create(_createPlain);
  }

  /// Settings read before any request reflect the plain client.
  HttpClient get _any {
    if (_closed) throw StateError('HttpClient is closed');
    return _plain ?? _withCertificate ?? (_plain = _create(_createPlain));
  }

  void _set(Object key, void Function(HttpClient) update) {
    if (_closed) throw StateError('HttpClient is closed');
    for (final client in [_plain, _withCertificate]) {
      if (client != null) update(client);
    }
    _settings[key] = update;
  }

  @override
  Future<HttpClientRequest> open(
    String method,
    String host,
    int port,
    String path,
  ) =>
      _clientFor(host).open(method, host, port, path);
  @override
  Future<HttpClientRequest> openUrl(String method, Uri url) =>
      _clientFor(url.host).openUrl(method, url);
  @override
  Future<HttpClientRequest> get(String host, int port, String path) =>
      open('GET', host, port, path);
  @override
  Future<HttpClientRequest> getUrl(Uri url) => openUrl('GET', url);
  @override
  Future<HttpClientRequest> post(String host, int port, String path) =>
      open('POST', host, port, path);
  @override
  Future<HttpClientRequest> postUrl(Uri url) => openUrl('POST', url);
  @override
  Future<HttpClientRequest> put(String host, int port, String path) =>
      open('PUT', host, port, path);
  @override
  Future<HttpClientRequest> putUrl(Uri url) => openUrl('PUT', url);
  @override
  Future<HttpClientRequest> delete(String host, int port, String path) =>
      open('DELETE', host, port, path);
  @override
  Future<HttpClientRequest> deleteUrl(Uri url) => openUrl('DELETE', url);
  @override
  Future<HttpClientRequest> patch(String host, int port, String path) =>
      open('PATCH', host, port, path);
  @override
  Future<HttpClientRequest> patchUrl(Uri url) => openUrl('PATCH', url);
  @override
  Future<HttpClientRequest> head(String host, int port, String path) =>
      open('HEAD', host, port, path);
  @override
  Future<HttpClientRequest> headUrl(Uri url) => openUrl('HEAD', url);

  @override
  Duration get idleTimeout => _any.idleTimeout;
  @override
  set idleTimeout(Duration value) =>
      _set('idleTimeout', (client) => client.idleTimeout = value);
  @override
  Duration? get connectionTimeout => _any.connectionTimeout;
  @override
  set connectionTimeout(Duration? value) =>
      _set('connectionTimeout', (client) => client.connectionTimeout = value);
  @override
  int? get maxConnectionsPerHost => _any.maxConnectionsPerHost;
  @override
  set maxConnectionsPerHost(int? value) => _set(
        'maxConnectionsPerHost',
        (client) => client.maxConnectionsPerHost = value,
      );
  @override
  bool get autoUncompress => _any.autoUncompress;
  @override
  set autoUncompress(bool value) =>
      _set('autoUncompress', (client) => client.autoUncompress = value);
  @override
  String? get userAgent => _any.userAgent;
  @override
  set userAgent(String? value) =>
      _set('userAgent', (client) => client.userAgent = value);
  @override
  set authenticate(
    Future<bool> Function(Uri url, String scheme, String? realm)? value,
  ) =>
      _set('authenticate', (client) => client.authenticate = value);
  @override
  void addCredentials(
    Uri url,
    String realm,
    HttpClientCredentials credentials,
  ) =>
      _set((
        'credentials',
        url,
        realm,
      ), (client) => client.addCredentials(url, realm, credentials));
  @override
  set connectionFactory(
    Future<ConnectionTask<Socket>> Function(
      Uri url,
      String? proxyHost,
      int? proxyPort,
    )? value,
  ) =>
      _set('connectionFactory', (client) => client.connectionFactory = value);
  @override
  set findProxy(String Function(Uri url)? value) =>
      _set('findProxy', (client) => client.findProxy = value);
  @override
  set authenticateProxy(
    Future<bool> Function(String host, int port, String scheme, String? realm)?
        value,
  ) =>
      _set('authenticateProxy', (client) => client.authenticateProxy = value);
  @override
  void addProxyCredentials(
    String host,
    int port,
    String realm,
    HttpClientCredentials credentials,
  ) =>
      _set(
          (
            'proxyCredentials',
            host,
            port,
            realm,
          ),
          (client) =>
              client.addProxyCredentials(host, port, realm, credentials));
  @override
  set badCertificateCallback(
    bool Function(X509Certificate cert, String host, int port)? value,
  ) =>
      _set(
        'badCertificateCallback',
        (client) => client.badCertificateCallback = value,
      );
  @override
  set keyLog(Function(String line)? value) =>
      _set('keyLog', (client) => client.keyLog = value);

  @override
  void close({bool force = false}) {
    if (_closed) return;
    _closed = true;
    _plain?.close(force: force);
    _withCertificate?.close(force: force);
    _plain = null;
    _withCertificate = null;
    _settings.clear();
  }
}
