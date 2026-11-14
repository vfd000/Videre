import 'dart:io';

import 'package:clipious/globals.dart';
import 'package:clipious/settings/models/db/settings.dart';
import 'network/client_certificate.dart';
import 'network/client_certificate_http_client.dart';
import 'network/gateway_http_client.dart';
import 'network/nerdvpn_origin.dart';
import 'network/network_proxy.dart';
import 'network/reloadable_http_client.dart';

class MyHttpOverrides extends HttpOverrides {
  // A separately installed test build can use the normal app request identity.
  // Release builds omit this define and keep their package-derived identity.
  static const _buildUserAgent = String.fromEnvironment('VIDERE_USER_AGENT');

  @override
  HttpClient createHttpClient(SecurityContext? context) {
    HttpClient build(SecurityContext? securityContext) {
      final client = super.createHttpClient(securityContext)
        ..userAgent = _buildUserAgent.isNotEmpty
            ? _buildUserAgent
            : 'Videre/${packageInfo?.version ?? '0.0.0'} (${packageInfo?.packageName ?? ''})'
        ..badCertificateCallback =
            (X509Certificate cert, String host, int port) {
          // Managed credentials require a valid certificate on both public
          // and onion HTTPS origins, regardless of other servers' overrides.
          if (isNerdVpnUrl(
              Uri(scheme: 'https', host: host, port: port).toString())) {
            return false;
          }
          // if true, it will allow all certs, if false it will throw error on a bad cert
          return db.getSettings(skipSslVerificationSettingName)?.value ==
              'true';
        };
      NetworkProxy.instance.configureClient(client, context: securityContext);
      return client;
    }

    return ReloadableHttpClient(() {
      // A caller's own SecurityContext is kept as is. Otherwise the mTLS
      // client certificate is presented only to the hosts selected for it.
      final certificate =
          context == null ? ClientCertificates.instance.current : null;
      return GatewayHttpClient(certificate == null
          ? build(context)
          : ClientCertificateRoutingHttpClient(
              plain: () => build(null),
              withCertificate: () => build(certificate.context),
              presentsTo: certificate.presentsTo));
    });
  }
}
