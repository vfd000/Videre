import 'package:flutter/material.dart';
import 'package:intl/intl.dart';

import '../../../l10n/generated/app_localizations.dart';
import '../../../network/watch_auth.dart';
import '../../../utils/motion.dart';
import '../../models/db/server.dart';

/// After a single sign-on, Invidious still needs its own token for account
/// features. The browser already holds the SSO session, so this is one tap.
Future<void> offerInvidiousTokenLogin(
    BuildContext context, Future<void> Function() logIn) async {
  final locals = AppLocalizations.of(context)!;
  final accepted = await showDialog<bool>(
      context: context,
      animationStyle: AppMotion.dialogStyle(context),
      builder: (context) => AlertDialog(
              title: Text(locals.ssoTokenLoginTitle),
              content: Text(locals.ssoTokenLoginHelp),
              actions: [
                TextButton(
                    onPressed: () => Navigator.of(context).pop(false),
                    child: Text(locals.ssoNotNow)),
                FilledButton.tonal(
                    onPressed: () => Navigator.of(context).pop(true),
                    child: Text(locals.tokenLogin))
              ]));
  if (accepted == true) await logIn();
}

/// Single sign-on status for servers that publish /.well-known/watch-auth.
class WatchAuthSettings extends StatefulWidget {
  final Server account;
  final bool authenticating;

  /// Starts the existing Invidious token sign-in for this account.
  final Future<void> Function() onTokenLogin;

  const WatchAuthSettings(
      {super.key,
      required this.account,
      required this.authenticating,
      required this.onTokenLogin});

  @override
  State<WatchAuthSettings> createState() => _WatchAuthSettingsState();
}

class _WatchAuthSettingsState extends State<WatchAuthSettings> {
  late Future<WatchAuthDiscovery?> _discovery;
  bool _busy = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _discovery = _discover();
  }

  @override
  void didUpdateWidget(WatchAuthSettings oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.account.url != widget.account.url ||
        oldWidget.account.accountId != widget.account.accountId) {
      _discovery = _discover();
    }
  }

  Future<WatchAuthDiscovery?> _discover() =>
      WatchAuth.accountKey(widget.account) == null
          ? Future.value(null)
          : WatchAuth.instance.discover(widget.account.url,
              headers: widget.account.customHeaders);

  Future<void> _signIn() async {
    if (_busy || widget.authenticating) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final discovery = await _discovery;
      final session =
          await WatchAuth.instance.signIn(widget.account, discovery: discovery);
      if (!mounted) return;
      if (session != null && (widget.account.authToken?.isEmpty ?? true)) {
        await offerInvidiousTokenLogin(context, widget.onTokenLogin);
      }
    } on WatchAuthException catch (error) {
      if (mounted) setState(() => _error = error.message);
    } catch (_) {
      if (!mounted) return;
      setState(() => _error = AppLocalizations.of(context)!.ssoFailed);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _signOut() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await WatchAuth.instance.signOut(widget.account);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) => ValueListenableBuilder<int>(
      valueListenable: WatchAuth.instance.revision,
      builder: (context, _, __) => FutureBuilder<WatchAuthDiscovery?>(
          future: _discovery,
          builder: (context, snapshot) {
            final session = WatchAuth.instance.sessionFor(widget.account);
            if (session == null && snapshot.data == null) {
              return const SizedBox.shrink();
            }
            final locals = AppLocalizations.of(context)!;
            final theme = Theme.of(context);
            final String status;
            final IconData icon;
            if (session == null) {
              status = locals.ssoNotSignedIn;
              icon = Icons.login;
            } else if (session.needsSignIn) {
              status = locals.ssoSignInNeeded;
              icon = Icons.warning_amber_outlined;
            } else {
              final expires = DateFormat.yMMMd(
                      Localizations.localeOf(context).toLanguageTag())
                  .add_jm()
                  .format(session.expiresAt.toLocal());
              status =
                  '${locals.ssoSignedInAs(session.email ?? '—')}\n${locals.ssoExpires(expires)}';
              icon = Icons.verified_user_outlined;
            }
            final disabled = _busy || widget.authenticating;
            return Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(children: [
                        Icon(icon,
                            color: session?.needsSignIn == true
                                ? theme.colorScheme.error
                                : null),
                        const SizedBox(width: 16),
                        Expanded(
                            child: Text(locals.ssoTitle,
                                style: theme.textTheme.titleMedium))
                      ]),
                      const SizedBox(height: 8),
                      Text(status),
                      if (_error != null) ...[
                        const SizedBox(height: 8),
                        Text(_error!,
                            style: TextStyle(color: theme.colorScheme.error))
                      ],
                      const SizedBox(height: 8),
                      Wrap(spacing: 8, runSpacing: 8, children: [
                        FilledButton.tonal(
                            onPressed: disabled ? null : _signIn,
                            child: Text(session == null
                                ? locals.ssoSignIn
                                : locals.ssoSignInAgain)),
                        if (session != null)
                          TextButton(
                              onPressed: _busy ? null : _signOut,
                              child: Text(locals.ssoSignOut))
                      ])
                    ]));
          }));
}
