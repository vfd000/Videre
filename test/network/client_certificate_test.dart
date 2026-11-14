import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:clipious/network/client_certificate.dart';
import 'package:clipious/network/client_certificate_http_client.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

// Self-signed, non-sensitive fixtures (see test/network/fixtures).
// client_legacy.p12: SHA1 MAC + PBE-SHA1-3DES, the Android-compatible form.
// client_aes.p12: OpenSSL 3 default, PBES2 AES-256-CBC + HMAC-SHA256 MAC.
const _password = 'test-password';

Uint8List _fixture(String name) =>
    File('test/network/fixtures/$name').readAsBytesSync();

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('host selection', () {
    test('normalizes hosts and accepts pasted URLs', () {
      expect(normalizeCertificateHost(' Watch.Liess.TV. '), 'watch.liess.tv');
      expect(
        normalizeCertificateHost('https://watch.liess.tv/feed?x=1'),
        'watch.liess.tv',
      );
      expect(normalizeCertificateHost('[::1]'), '::1');
      expect(normalizeCertificateHost('10.0.0.5'), '10.0.0.5');
      expect(normalizeCertificateHost('watch.liess.tv/feed'), isNull);
      expect(normalizeCertificateHost('user@watch.liess.tv'), isNull);
      expect(normalizeCertificateHost('a..b'), isNull);
      expect(normalizeCertificateHost(''), isNull);
      expect(normalizeCertificateHost('bücher.example'), isNull);
    });

    test('parses a host list with wildcards and rejects invalid entries', () {
      expect(parseCertificateHosts('watch.liess.tv\n*.Example.com, a.b;a.b'), [
        'watch.liess.tv',
        '*.example.com',
        'a.b',
      ]);
      expect(parseCertificateHosts('  '), isEmpty);
      expect(parseCertificateHosts('watch.liess.tv\nhttp//bad/'), isNull);
      expect(parseCertificateHosts('*.'), isNull);
    });

    test('matches exact hosts and subdomains of wildcard patterns only', () {
      const hosts = ['watch.liess.tv', '*.example.com'];
      expect(clientCertificateHostSelected(hosts, 'watch.liess.tv'), isTrue);
      expect(clientCertificateHostSelected(hosts, 'WATCH.liess.tv.'), isTrue);
      expect(clientCertificateHostSelected(hosts, 'liess.tv'), isFalse);
      expect(
        clientCertificateHostSelected(hosts, 'evil-watch.liess.tv'),
        isFalse,
      );
      expect(
        clientCertificateHostSelected(hosts, 'watch.liess.tv.evil.com'),
        isFalse,
      );
      expect(clientCertificateHostSelected(hosts, 'a.example.com'), isTrue);
      expect(clientCertificateHostSelected(hosts, 'example.com'), isFalse);
      expect(clientCertificateHostSelected(hosts, 'notexample.com'), isFalse);
      expect(
        clientCertificateHostSelected(const [], 'watch.liess.tv'),
        isFalse,
      );
    });
  });

  group('routing client', () {
    Future<HttpServer> proxy(String label) async {
      final server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() => server.close(force: true));
      server.listen((request) {
        request.response.write(
          '$label|${request.headers.host}|'
          '${request.headers.value(HttpHeaders.userAgentHeader)}',
        );
        unawaited(request.response.close());
      });
      return server;
    }

    Future<String> read(HttpClient client, String url) async {
      final request = await client.getUrl(Uri.parse(url));
      final response = await request.close();
      return response.transform(utf8.decoder).join();
    }

    test('sends selected hosts through the certificate client only', () async {
      final plain = await proxy('plain');
      final certified = await proxy('certificate');
      var plainCreated = 0;
      var certifiedCreated = 0;
      final selection = ClientCertificateContext(
        SecurityContext(withTrustedRoots: false),
        ['watch.liess.tv'],
      );
      final client = ClientCertificateRoutingHttpClient(
        plain: () {
          plainCreated++;
          return HttpClient()
            ..findProxy = (_) => 'PROXY 127.0.0.1:${plain.port}';
        },
        withCertificate: () {
          certifiedCreated++;
          return HttpClient()
            ..findProxy = (_) => 'PROXY 127.0.0.1:${certified.port}';
        },
        presentsTo: selection.presentsTo,
      )..userAgent = 'consumer';
      addTearDown(() => client.close(force: true));

      expect(
        await read(client, 'http://other.invalid/a'),
        'plain|other.invalid|consumer',
      );
      expect(certifiedCreated, 0);
      expect(
        await read(client, 'http://WATCH.liess.tv/api/v1/stats'),
        'certificate|watch.liess.tv|consumer',
      );
      expect(
        await read(client, 'http://watch.liess.tv.invalid/x'),
        startsWith('plain|'),
      );
      expect(
        await read(client, 'http://watch.liess.tv/y'),
        startsWith('certificate|'),
      );
      expect(plainCreated, 1);
      expect(certifiedCreated, 1);

      // Settings changed later reach both underlying clients.
      client.userAgent = 'changed';
      expect(await read(client, 'http://other.invalid/b'), endsWith('changed'));
      expect(
        await read(client, 'http://watch.liess.tv/c'),
        endsWith('changed'),
      );
    });

    test('a closed client refuses new requests', () async {
      final client = ClientCertificateRoutingHttpClient(
        plain: HttpClient.new,
        withCertificate: HttpClient.new,
        presentsTo: (_) => false,
      )..close();
      expect(
        () => client.getUrl(Uri.parse('http://other.invalid/')),
        throwsStateError,
      );
    });
  });

  group('PKCS#12 loading', () {
    test('loads the Android-compatible legacy file', () {
      expect(
        clientCertificateSecurityContext(
          _fixture('client_legacy.p12'),
          _password,
        ),
        isA<SecurityContext>(),
      );
    });

    test('loads a modern AES-encrypted file', () {
      expect(
        clientCertificateSecurityContext(_fixture('client_aes.p12'), _password),
        isA<SecurityContext>(),
      );
    });

    test('rejects a wrong password', () {
      expect(
        () => clientCertificateSecurityContext(
          _fixture('client_legacy.p12'),
          'wrong',
        ),
        throwsA(isA<TlsException>()),
      );
    });
  });

  group('platform store', () {
    const channel = MethodChannel('videre/proxy');
    final messenger =
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    tearDown(() => messenger.setMockMethodCallHandler(channel, null));

    test('loads stored material for the Dart transport', () async {
      final fixture = _fixture('client_legacy.p12');
      messenger.setMockMethodCallHandler(channel, (call) async {
        expect(call.method, 'clientCertificateMaterial');
        return {
          'pkcs12': fixture,
          'password': _password,
          'hosts': ['watch.liess.tv'],
        };
      });
      final certificates = ClientCertificates.forTesting(
        supported: true,
        channel: channel,
      );
      await certificates.initialize();
      expect(certificates.current, isNotNull);
      expect(certificates.current!.presentsTo('watch.liess.tv'), isTrue);
      expect(certificates.current!.presentsTo('youtube.com'), isFalse);
    });

    test('a failed load leaves requests without a certificate', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        throw PlatformException(code: 'CLIENT_CERTIFICATE', message: 'x');
      });
      final certificates = ClientCertificates.forTesting(
        supported: true,
        channel: channel,
      );
      await certificates.initialize();
      expect(certificates.current, isNull);
    });

    test('reports platform reasons and an unreadable stored file', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        if (call.method == 'clientCertificateStatus') {
          return {'error': 'unreadable'};
        }
        throw PlatformException(
          code: 'CLIENT_CERTIFICATE',
          message: 'wrongPassword',
        );
      });
      final certificates = ClientCertificates.forTesting(
        supported: true,
        channel: channel,
      );
      await expectLater(
        certificates.status(),
        throwsA(
          isA<ClientCertificateFailure>().having(
            (error) => error.reason,
            'reason',
            'unreadable',
          ),
        ),
      );
      await expectLater(
        certificates.inspect(Uint8List(4), 'wrong'),
        throwsA(
          isA<ClientCertificateFailure>().having(
            (error) => error.reason,
            'reason',
            'wrongPassword',
          ),
        ),
      );
    });

    test('parses certificate details', () async {
      messenger.setMockMethodCallHandler(channel, (call) async {
        return {
          'commonName': 'phone',
          'subject': 'CN=phone,O=Home',
          'issuer': 'CN=Gatekeeper CA',
          'notBefore': 0,
          'notAfter': DateTime.utc(2030).millisecondsSinceEpoch,
          'hosts': ['watch.liess.tv'],
        };
      });
      final info = await ClientCertificates.forTesting(
        supported: true,
        channel: channel,
      ).status();
      expect(info!.commonName, 'phone');
      expect(info.hosts, ['watch.liess.tv']);
      expect(info.expiredAt(DateTime.utc(2029)), isFalse);
      expect(info.expiredAt(DateTime.utc(2031)), isTrue);
    });

    test('is unavailable off Android without touching the channel', () async {
      final certificates = ClientCertificates.forTesting(
        supported: false,
        channel: channel,
      );
      await certificates.initialize();
      expect(await certificates.status(), isNull);
      expect(certificates.current, isNull);
    });
  });
}
