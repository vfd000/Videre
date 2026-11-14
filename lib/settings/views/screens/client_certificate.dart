import 'package:clipious/globals.dart';
import 'package:clipious/l10n/generated/app_localizations.dart';
import 'package:clipious/network/client_certificate.dart';
import 'package:clipious/utils/motion.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

/// Hosts of the configured servers, the default selection for a new certificate.
Future<List<String>> configuredServerHosts() async {
  final hosts = <String>[];
  for (final server in await db.getServers()) {
    final host = normalizeCertificateHost(Uri.tryParse(server.url)?.host ?? '');
    if (host != null && !hosts.contains(host)) hosts.add(host);
  }
  return hosts;
}

Future<Uint8List?> _pickCertificateFile() =>
    const MethodChannel('videre/files').invokeMethod<Uint8List>('openBinary');

String clientCertificateErrorText(AppLocalizations locals, Object error) {
  final reason = error is ClientCertificateFailure ? error.reason : '';
  return switch (reason) {
    'wrongPassword' => locals.clientCertificateWrongPassword,
    'unsupported' => locals.clientCertificateUnsupported,
    'invalidFile' || 'noKey' => locals.clientCertificateInvalidFile,
    'transport' => locals.clientCertificateTransportUnsupported,
    'unreadable' => locals.clientCertificateUnreadable,
    'invalidHost' => locals.clientCertificateInvalidHosts,
    _ => locals.clientCertificateFailed,
  };
}

class _Pending {
  final Uint8List pkcs12;
  final String password;
  final ClientCertificateInfo info;

  _Pending(this.pkcs12, this.password, this.info);
}

/// Owns its controller so the field outlives the dialog's exit animation.
class _PasswordDialog extends StatefulWidget {
  const _PasswordDialog();

  @override
  State<_PasswordDialog> createState() => _PasswordDialogState();
}

class _PasswordDialogState extends State<_PasswordDialog> {
  final _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final locals = AppLocalizations.of(context)!;
    return AlertDialog(
      title: Text(locals.clientCertificatePasswordTitle),
      content: TextField(
        controller: _controller,
        autofocus: true,
        obscureText: true,
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        decoration: InputDecoration(
          labelText: locals.clientCertificatePassword,
        ),
        onSubmitted: (value) => Navigator.pop(context, value),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(locals.cancel),
        ),
        FilledButton(
          onPressed: () => Navigator.pop(context, _controller.text),
          child: Text(locals.ok),
        ),
      ],
    );
  }
}

class ClientCertificateSettingsScreen extends StatefulWidget {
  final ClientCertificates? certificates;
  final Future<Uint8List?> Function()? pickFile;
  final Future<List<String>> Function()? defaultHosts;

  const ClientCertificateSettingsScreen({
    super.key,
    this.certificates,
    this.pickFile,
    this.defaultHosts,
  });

  @override
  State<ClientCertificateSettingsScreen> createState() =>
      _ClientCertificateSettingsScreenState();
}

class _ClientCertificateSettingsScreenState
    extends State<ClientCertificateSettingsScreen> {
  final _formKey = GlobalKey<FormState>();
  final _hosts = TextEditingController();
  late final ClientCertificates _certificates =
      widget.certificates ?? ClientCertificates.instance;
  ClientCertificateInfo? _stored;
  _Pending? _pending;
  bool _loading = true;
  bool _busy = false;
  String? _status;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _hosts.dispose();
    super.dispose();
  }

  Future<List<String>> _defaultHosts() async {
    try {
      return await (widget.defaultHosts ?? configuredServerHosts)();
    } catch (_) {
      return const [];
    }
  }

  Future<void> _load() async {
    ClientCertificateInfo? stored;
    Object? failure;
    try {
      stored = await _certificates.status();
    } catch (error) {
      failure = error;
    }
    final hosts = stored?.hosts ?? await _defaultHosts();
    if (!mounted) return;
    final locals = AppLocalizations.of(context)!;
    setState(() {
      _stored = stored;
      _hosts.text = hosts.join('\n');
      _loading = false;
      if (failure != null) {
        _failed = true;
        _status = clientCertificateErrorText(locals, failure);
      }
    });
  }

  void _report(String message, {bool failed = false}) {
    if (!mounted) return;
    setState(() {
      _status = message;
      _failed = failed;
    });
  }

  Future<String?> _askPassword() => showDialog<String>(
        context: context,
        animationStyle: AppMotion.dialogStyle(context),
        builder: (context) => const _PasswordDialog(),
      );

  Future<void> _import() async {
    final locals = AppLocalizations.of(context)!;
    setState(() => _status = null);
    final Uint8List? bytes;
    try {
      bytes = await (widget.pickFile ?? _pickCertificateFile)();
    } on PlatformException catch (error) {
      _report(error.message ?? locals.clientCertificateFailed, failed: true);
      return;
    }
    if (bytes == null || !mounted) return;
    final password = await _askPassword();
    if (password == null || !mounted) return;
    setState(() => _busy = true);
    try {
      final info = await _certificates.inspect(bytes, password);
      if (!mounted) return;
      final pending = _Pending(bytes, password, info);
      final hosts = _stored == null ? await _defaultHosts() : null;
      if (!mounted) return;
      setState(() {
        _pending = pending;
        if (hosts != null && _hosts.text.trim().isEmpty) {
          _hosts.text = hosts.join('\n');
        }
      });
      _report(locals.clientCertificatePending);
    } catch (error) {
      _report(clientCertificateErrorText(locals, error), failed: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _save() async {
    if (!_formKey.currentState!.validate()) return;
    final locals = AppLocalizations.of(context)!;
    final hosts = parseCertificateHosts(_hosts.text)!;
    setState(() {
      _busy = true;
      _status = null;
    });
    try {
      final pending = _pending;
      final saved = pending != null
          ? await _certificates.save(pending.pkcs12, pending.password, hosts)
          : await _certificates.setHosts(hosts);
      if (!mounted) return;
      setState(() {
        _stored = saved;
        _pending = null;
        if (saved != null) _hosts.text = saved.hosts.join('\n');
      });
      _report(locals.clientCertificateSaved);
    } catch (error) {
      _report(clientCertificateErrorText(locals, error), failed: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _remove() async {
    final locals = AppLocalizations.of(context)!;
    final confirmed = await showDialog<bool>(
      context: context,
      animationStyle: AppMotion.dialogStyle(context),
      builder: (context) => AlertDialog(
        content: Text(locals.clientCertificateRemoveConfirm),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text(locals.cancel),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, true),
            child: Text(locals.clientCertificateRemove),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    setState(() => _busy = true);
    try {
      await _certificates.remove();
      final hosts = await _defaultHosts();
      if (!mounted) return;
      setState(() {
        _stored = null;
        _hosts.text = hosts.join('\n');
      });
      _report(locals.clientCertificateRemoved);
    } catch (error) {
      _report(clientCertificateErrorText(locals, error), failed: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Widget _details(ClientCertificateInfo info) {
    final locals = AppLocalizations.of(context)!;
    final colors = Theme.of(context).colorScheme;
    final material = MaterialLocalizations.of(context);
    final expired = info.expiredAt(DateTime.now());
    final date = material.formatMediumDate(info.notAfter);
    return Card(
      margin: EdgeInsets.zero,
      child: ListTile(
        leading: const Icon(Icons.badge_outlined),
        title: Text(locals.clientCertificateSubject(info.commonName)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (info.issuer.isNotEmpty)
              Text(locals.clientCertificateIssuer(info.issuer)),
            Text(
              expired
                  ? locals.clientCertificateExpired(date)
                  : locals.clientCertificateExpires(date),
              style: expired ? TextStyle(color: colors.error) : null,
            ),
          ],
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final locals = AppLocalizations.of(context)!;
    final colors = Theme.of(context).colorScheme;
    final shown = _pending?.info ?? _stored;
    return Scaffold(
      appBar: AppBar(title: Text(locals.clientCertificate)),
      body: SafeArea(
        child: Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 720),
            child: Form(
              key: _formKey,
              child: ListView(
                padding: const EdgeInsets.all(24),
                children: [
                  Text(locals.clientCertificateDescription),
                  const SizedBox(height: 16),
                  if (!_certificates.supported)
                    Text(locals.clientCertificateUnavailable)
                  else if (_loading)
                    const MotionLoadingIndicator(
                      child: LinearProgressIndicator(),
                    )
                  else ...[
                    if (shown == null)
                      Text(locals.clientCertificateNone)
                    else
                      _details(shown),
                    const SizedBox(height: 16),
                    TextFormField(
                      controller: _hosts,
                      enabled: !_busy && shown != null,
                      minLines: 2,
                      maxLines: 6,
                      decoration: InputDecoration(
                        labelText: locals.clientCertificateHosts,
                        helperText: locals.clientCertificateHostsHelp,
                        helperMaxLines: 3,
                      ),
                      autocorrect: false,
                      enableSuggestions: false,
                      keyboardType: TextInputType.multiline,
                      onChanged: (_) => setState(() => _status = null),
                      validator: (value) {
                        final hosts = parseCertificateHosts(value ?? '');
                        if (hosts == null) {
                          return locals.clientCertificateInvalidHosts;
                        }
                        if (hosts.isEmpty)
                          return locals.clientCertificateNoHosts;
                        return null;
                      },
                    ),
                    const SizedBox(height: 24),
                    Wrap(
                      spacing: 16,
                      runSpacing: 12,
                      children: [
                        OutlinedButton.icon(
                          autofocus: true,
                          onPressed: _busy ? null : _import,
                          icon: const Icon(Icons.file_open_outlined),
                          label: Text(
                            _stored == null && _pending == null
                                ? locals.clientCertificateImport
                                : locals.clientCertificateReplace,
                          ),
                        ),
                        FilledButton(
                          onPressed: _busy || shown == null ? null : _save,
                          child: Text(locals.save),
                        ),
                        if (_stored != null && _pending == null)
                          TextButton(
                            onPressed: _busy ? null : _remove,
                            child: Text(locals.clientCertificateRemove),
                          ),
                      ],
                    ),
                  ],
                  if (_busy) ...[
                    const SizedBox(height: 16),
                    const MotionLoadingIndicator(
                      child: LinearProgressIndicator(),
                    ),
                  ],
                  if (_status != null) ...[
                    const SizedBox(height: 16),
                    Semantics(
                      liveRegion: true,
                      child: Text(
                        _status!,
                        style: TextStyle(color: _failed ? colors.error : null),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
