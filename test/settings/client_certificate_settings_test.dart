import 'dart:io';

import 'package:clipious/l10n/generated/app_localizations.dart';
import 'package:clipious/network/client_certificate.dart';
import 'package:clipious/settings/views/screens/client_certificate.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('videre/proxy');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));

  // Self-signed, non-sensitive fixture: CN=videre-test-client.
  final fixture = File(
    'test/network/fixtures/client_legacy.p12',
  ).readAsBytesSync();

  Map<String, Object?> details(List<Object?> hosts) => {
        'commonName': 'videre-test-client',
        'subject': 'CN=videre-test-client',
        'issuer': 'CN=videre-test-client',
        'notBefore': 0,
        'notAfter': DateTime.utc(2099).millisecondsSinceEpoch,
        'hosts': hosts,
      };

  Future<void> pump(WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        localizationsDelegates: AppLocalizations.localizationsDelegates,
        supportedLocales: AppLocalizations.supportedLocales,
        home: ClientCertificateSettingsScreen(
          certificates: ClientCertificates.forTesting(
            supported: true,
            channel: channel,
          ),
          pickFile: () async => fixture,
          defaultHosts: () async => ['watch.liess.tv'],
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  Future<void> tap(WidgetTester tester, String label) async {
    final target = find.text(label);
    await tester.ensureVisible(target);
    await tester.pumpAndSettle();
    await tester.tap(target);
    await tester.pumpAndSettle();
  }

  testWidgets('imports a certificate for the configured server hosts', (
    tester,
  ) async {
    final calls = <MethodCall>[];
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return switch (call.method) {
        'clientCertificateStatus' => <String, Object?>{},
        'inspectClientCertificate' => details(const []),
        'importClientCertificate' => details(
            (call.arguments as Map)['hosts'] as List<Object?>,
          ),
        'clientCertificateMaterial' => null,
        _ => throw MissingPluginException(),
      };
    });
    await pump(tester);
    expect(find.text('No client certificate is installed.'), findsOneWidget);

    await tap(tester, 'Import .p12 file');
    await tester.enterText(
      find.widgetWithText(TextField, 'Certificate password'),
      'test-password',
    );
    await tap(tester, 'OK');

    expect(find.text('Certificate: videre-test-client'), findsOneWidget);
    expect(
      find.text('Not saved yet. Check the hosts, then save.'),
      findsOneWidget,
    );
    expect(find.text('watch.liess.tv'), findsOneWidget);

    await tap(tester, 'Save');
    final saved = calls.singleWhere(
      (call) => call.method == 'importClientCertificate',
    );
    final arguments = saved.arguments as Map;
    expect(arguments['hosts'], ['watch.liess.tv']);
    expect(arguments['password'], 'test-password');
    expect(arguments['pkcs12'], fixture);
    expect(find.text('Client certificate saved.'), findsOneWidget);
    expect(find.text('Remove certificate'), findsOneWidget);
  });

  testWidgets('shows a wrong password without saving', (tester) async {
    final methods = <String>[];
    messenger.setMockMethodCallHandler(channel, (call) async {
      methods.add(call.method);
      if (call.method == 'clientCertificateStatus') return <String, Object?>{};
      throw PlatformException(
        code: 'CLIENT_CERTIFICATE',
        message: 'wrongPassword',
      );
    });
    await pump(tester);
    await tap(tester, 'Import .p12 file');
    await tester.enterText(
      find.widgetWithText(TextField, 'Certificate password'),
      'nope',
    );
    await tap(tester, 'OK');

    expect(find.text('The password is incorrect.'), findsOneWidget);
    expect(methods, isNot(contains('importClientCertificate')));
  });

  testWidgets('edits hosts and removes a stored certificate', (tester) async {
    final calls = <MethodCall>[];
    var stored = true;
    messenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      return switch (call.method) {
        'clientCertificateStatus' =>
          stored ? details(['watch.liess.tv']) : <String, Object?>{},
        'setClientCertificateHosts' => details(
            (call.arguments as Map)['hosts'] as List<Object?>,
          ),
        'clientCertificateMaterial' => null,
        'removeClientCertificate' => () {
            stored = false;
            return null;
          }(),
        _ => throw MissingPluginException(),
      };
    });
    await pump(tester);
    expect(find.text('Certificate: videre-test-client'), findsOneWidget);

    await tester.enterText(
      find.widgetWithText(TextFormField, 'Present to hosts'),
      'watch.liess.tv/feed',
    );
    await tap(tester, 'Save');
    expect(
      find.text(
        'Enter host names such as watch.example.com, without paths or ports.',
      ),
      findsOneWidget,
    );
    expect(
      calls.map((call) => call.method),
      isNot(contains('setClientCertificateHosts')),
    );

    await tester.enterText(
      find.widgetWithText(TextFormField, 'Present to hosts'),
      'watch.liess.tv\n*.liess.tv',
    );
    await tap(tester, 'Save');
    final update = calls.singleWhere(
      (call) => call.method == 'setClientCertificateHosts',
    );
    expect((update.arguments as Map)['hosts'], [
      'watch.liess.tv',
      '*.liess.tv',
    ]);

    await tap(tester, 'Remove certificate');
    await tester.tap(find.widgetWithText(FilledButton, 'Remove certificate'));
    await tester.pumpAndSettle();
    expect(
      calls.map((call) => call.method),
      contains('removeClientCertificate'),
    );
    expect(find.text('Client certificate removed.'), findsOneWidget);
    expect(find.text('No client certificate is installed.'), findsOneWidget);
  });
}
