import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:logging/logging.dart';

import 'reloadable_http_client.dart';

/// Lower-cases and strips a trailing dot. Returns null for anything that is
/// not an ASCII host name or IP literal. Accepts a pasted URL and keeps only
/// its host. Kept in step with normalizeCertificateHost in ClientCertificateTls.kt.
String? normalizeCertificateHost(String input) {
  var value = input.trim();
  if (value.contains('://')) {
    final uri = Uri.tryParse(value);
    if (uri == null || uri.host.isEmpty) return null;
    value = uri.host;
  }
  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.substring(1, value.length - 1);
  }
  final host = value.toLowerCase().replaceFirst(RegExp(r'\.+$'), '');
  if (host.isEmpty || host.length > 253) return null;
  if (host.contains(':')) {
    return RegExp(r'^[0-9a-f:.]+$').hasMatch(host) ? host : null;
  }
  if (!RegExp(r'^[a-z0-9_-]+(\.[a-z0-9_-]+)*$').hasMatch(host)) return null;
  return host;
}

/// A selected host: an exact host, or `*.example.com` for its subdomains.
String? normalizeCertificateHostPattern(String input) {
  final value = input.trim();
  if (value.startsWith('*.')) {
    final host = normalizeCertificateHost(value.substring(2));
    return host == null ? null : '*.$host';
  }
  return normalizeCertificateHost(value);
}

bool clientCertificateHostSelected(Iterable<String> patterns, String host) {
  final target = normalizeCertificateHost(host);
  if (target == null) return false;
  return patterns.any(
    (pattern) => pattern.startsWith('*.')
        ? target.endsWith(pattern.substring(1))
        : pattern == target,
  );
}

/// Splits user input on commas, whitespace and new lines. Returns null when
/// any entry is not a valid host or `*.domain` pattern.
List<String>? parseCertificateHosts(String input) {
  final hosts = <String>[];
  for (final part in input.split(RegExp(r'[\s,;]+'))) {
    if (part.isEmpty) continue;
    final host = normalizeCertificateHostPattern(part);
    if (host == null) return null;
    if (!hosts.contains(host)) hosts.add(host);
  }
  return hosts;
}

/// Subject, validity and selected hosts of a client certificate.
class ClientCertificateInfo {
  final String commonName;
  final String subject;
  final String issuer;
  final DateTime notBefore;
  final DateTime notAfter;
  final List<String> hosts;

  const ClientCertificateInfo({
    required this.commonName,
    required this.subject,
    required this.issuer,
    required this.notBefore,
    required this.notAfter,
    this.hosts = const [],
  });

  static ClientCertificateInfo? fromMap(Map<Object?, Object?>? map) {
    if (map == null || map['notAfter'] == null) return null;
    return ClientCertificateInfo(
      commonName: map['commonName'] as String? ?? '',
      subject: map['subject'] as String? ?? '',
      issuer: map['issuer'] as String? ?? '',
      notBefore: DateTime.fromMillisecondsSinceEpoch(
        (map['notBefore'] as num?)?.toInt() ?? 0,
      ),
      notAfter: DateTime.fromMillisecondsSinceEpoch(
        (map['notAfter'] as num).toInt(),
      ),
      hosts: [
        for (final host in map['hosts'] as List<Object?>? ?? const [])
          if (host is String) host,
      ],
    );
  }

  bool expiredAt(DateTime now) => now.isAfter(notAfter);
}

/// Why a certificate could not be imported, as reported by the platform.
class ClientCertificateFailure implements Exception {
  /// One of wrongPassword, unsupported, invalidFile, noKey, invalidHost,
  /// storage, transport (the Dart TLS stack cannot load it) or unavailable.
  final String reason;

  const ClientCertificateFailure(this.reason);

  @override
  String toString() => 'ClientCertificateFailure($reason)';
}

/// The certificate the Dart transport presents, with its host selection.
class ClientCertificateContext {
  final SecurityContext context;
  final List<String> hosts;

  ClientCertificateContext(this.context, this.hosts);

  bool presentsTo(String host) => clientCertificateHostSelected(hosts, host);
}

/// Builds a SecurityContext with platform roots and the PKCS#12 identity.
/// Throws a TlsException when BoringSSL cannot load the file.
SecurityContext clientCertificateSecurityContext(
  List<int> pkcs12,
  String password,
) {
  return SecurityContext(withTrustedRoots: true)
    ..useCertificateChainBytes(pkcs12, password: password)
    ..usePrivateKeyBytes(pkcs12, password: password);
}

/// Owns the mTLS client certificate. Android stores it natively (encrypted
/// with a Keystore key) so the OkHttp transport, workers and the sign-in
/// browser share it; the Dart transport keeps an in-memory SecurityContext.
class ClientCertificates {
  ClientCertificates._({bool? supported, MethodChannel? channel})
      : supported = supported ?? Platform.isAndroid,
        _channel = channel ?? const MethodChannel('videre/proxy');

  @visibleForTesting
  ClientCertificates.forTesting({
    required bool supported,
    MethodChannel? channel,
  }) : this._(supported: supported, channel: channel);

  static final instance = ClientCertificates._();

  final bool supported;
  final MethodChannel _channel;
  ClientCertificateContext? _current;

  /// The certificate for the Dart transport, or null when none is configured.
  ClientCertificateContext? get current => _current;

  @visibleForTesting
  set current(ClientCertificateContext? value) => _current = value;

  /// Loads the stored certificate for the Dart transport. Never throws: a
  /// failure leaves requests without a certificate, as before this feature.
  Future<void> initialize() async {
    if (!supported) return;
    try {
      await _reload();
    } catch (error) {
      Logger(
        'ClientCertificates',
      ).warning('Client certificate unavailable (${error.runtimeType}).');
      _current = null;
      ReloadableHttpClient.resetAll();
    }
  }

  Future<void> _reload() async {
    final material = await _channel.invokeMapMethod<String, Object?>(
      'clientCertificateMaterial',
    );
    final bytes = material?['pkcs12'];
    final password = material?['password'];
    final hosts = material?['hosts'];
    _current = bytes is Uint8List && password is String && hosts is List
        ? ClientCertificateContext(
            clientCertificateSecurityContext(bytes, password),
            [for (final host in hosts) host as String],
          )
        : null;
    ReloadableHttpClient.resetAll();
  }

  Future<T?> _invoke<T>(String method, [Object? arguments]) async {
    try {
      return await _channel.invokeMethod<T>(method, arguments);
    } on PlatformException catch (error) {
      throw ClientCertificateFailure(error.message ?? 'unavailable');
    }
  }

  /// The stored certificate, or null. Throws when the stored file cannot be
  /// decrypted any more (for example after restoring to another device).
  Future<ClientCertificateInfo?> status() async {
    if (!supported) return null;
    final map = await _invoke<Map<Object?, Object?>>('clientCertificateStatus');
    if (map?['error'] != null) {
      throw ClientCertificateFailure(map!['error'] as String);
    }
    return ClientCertificateInfo.fromMap(map);
  }

  /// Checks that both Android and the Dart TLS stack can load the file.
  Future<ClientCertificateInfo> inspect(
    Uint8List pkcs12,
    String password,
  ) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'inspectClientCertificate',
      {'pkcs12': pkcs12, 'password': password},
    );
    final info = ClientCertificateInfo.fromMap(map);
    if (info == null) throw const ClientCertificateFailure('invalidFile');
    try {
      clientCertificateSecurityContext(pkcs12, password);
    } on TlsException {
      throw const ClientCertificateFailure('transport');
    }
    return info;
  }

  Future<ClientCertificateInfo?> save(
    Uint8List pkcs12,
    String password,
    List<String> hosts,
  ) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'importClientCertificate',
      {'pkcs12': pkcs12, 'password': password, 'hosts': hosts},
    );
    await _reload();
    return ClientCertificateInfo.fromMap(map);
  }

  Future<ClientCertificateInfo?> setHosts(List<String> hosts) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'setClientCertificateHosts',
      {'hosts': hosts},
    );
    await _reload();
    return ClientCertificateInfo.fromMap(map);
  }

  Future<void> remove() async {
    await _invoke<void>('removeClientCertificate');
    _current = null;
    ReloadableHttpClient.resetAll();
  }
}
