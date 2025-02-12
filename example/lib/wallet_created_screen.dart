import 'package:clipboard/clipboard.dart';
import 'package:example/services/auth_service.dart';
import 'package:example/services/env_service.dart';
import 'package:example/services/navigation_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_passkey_kit/flutter_passkey_kit.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'auth_screen.dart';
import 'home_screen.dart';
import 'model/user_model.dart';

class WalletCreatedScreen extends StatefulWidget {
  final UserModel user;
  const WalletCreatedScreen({super.key, required this.user});

  @override
  State<WalletCreatedScreen> createState() => _WalletCreatedScreenState();

  static Future<void> logout() async {
    var prefs = await SharedPreferences.getInstance();
    prefs.remove('sp:contractId');
    prefs.remove('sp:credentialsId');
    prefs.remove('sp:username');
  }
}

class _WalletCreatedScreenState extends State<WalletCreatedScreen> {

  bool isConnectingWallet = false;
  String? errorMessage;
  PasskeyKit? passkeyKit;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'New Wallet',
          style: TextStyle(color: Colors.white),
        ),
        actions: [
          ElevatedButton.icon(
            onPressed: () async {
              await WalletCreatedScreen.logout();
              Navigator.of(NavigationService.navigatorKey.currentContext!).pushAndRemoveUntil(
                  MaterialPageRoute(
                      builder: (builder) => const AuthScreen(key: Key('auth_screen'))),
                      (predicate) => false);
            },
            label: const Text('Logout'),
            style: ElevatedButton.styleFrom(
              foregroundColor: Colors.white,
              backgroundColor: Colors.deepPurple,
              padding: const EdgeInsets.symmetric(
                  vertical: 12.0, horizontal: 24.0),
              textStyle: const TextStyle(fontSize: 20.0),
            ),
          ),
        ],
        backgroundColor: Colors.deepPurple,
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              const Icon(
                Icons.wallet_membership_rounded,
                color: Colors.deepPurple,
                size: 100,
              ),
              const SizedBox(height: 40),
              Text(
                'Hello ${widget.user.username}! This is your new smart wallet address:',
                style: const TextStyle(
                  fontSize: 24,
                  fontWeight: FontWeight.bold,
                  color: Colors.deepPurple,
                ),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    flex: 7,
                    child: Text(
                      widget.user.contractId,
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(
                      Icons.copy_outlined,
                      size: 20,
                    ),
                    onPressed: () => _copyToClipboard(widget.user.contractId),
                  ),
                ],
              ),
              const SizedBox(height: 30),
              const Text(
                'You can now connect to your wallet!',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: Colors.deepPurple,
                ),
              ),
              const SizedBox(height: 30),
              ElevatedButton.icon(
                onPressed: () async {
                  await connectWallet(widget.user);
                },
                icon: const Icon(Icons.login),
                label: const Text('Connect'),
                style: ElevatedButton.styleFrom(
                  foregroundColor: Colors.white,
                  backgroundColor: Colors.deepPurple,
                  padding: const EdgeInsets.symmetric(
                      vertical: 12.0, horizontal: 24.0),
                  textStyle: const TextStyle(fontSize: 16.0),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  PasskeyKit _getPasskeyKit() {
    passkeyKit ??= PasskeyKit(
        EnvService.getRpId(),
        EnvService.getRpcUrl(),
        EnvService.getWasmHash(),
        EnvService.getNetwork()
    );
    return passkeyKit!;
  }

  static Future<void> _save(UserModel user) async {
    var prefs = await SharedPreferences.getInstance();
    prefs.setString('sp:credentialsId', user.credentialsId);
    prefs.setString('sp:username', user.username);
    prefs.setString('sp:contractId', user.contractId);
  }

  Future<void> connectWallet(UserModel currentUser) async {
    setState(() {
      isConnectingWallet = true;
      errorMessage = null;
    });
    try {
      var kit = _getPasskeyKit();
      var result = await kit.connectWallet(AuthService.getPasskeyCredentials,
          keyId: currentUser.credentialsId);

      var user = UserModel(
          username: result.username != null ? result.username! : currentUser.username ,
          credentialsId: result.keyId,
          contractId: result.contractId);

      await _save(user);

      Navigator.of(NavigationService.navigatorKey.currentContext!).pushReplacement(
        MaterialPageRoute(
          builder: (context) => HomeScreen(
            user: user,
            kit: kit
          ),
        ),
      );
    } catch (e) {
      setState(() {
        errorMessage = 'Error: $e';
      });
    } finally {
      setState(() {
        isConnectingWallet = false;
      });
    }
  }

  void _copyToClipboard(String text) async {
    await FlutterClipboard.copy(text);
    _showCopied();
  }

  void _showCopied() {
    ScaffoldMessenger.of(NavigationService.navigatorKey.currentContext!)
        .showSnackBar(
      const SnackBar(
        content: Text('Copied to clipboard'),
        backgroundColor: Colors.green,
      ),
    );
  }
}
