import 'package:clipboard/clipboard.dart';
import 'package:example/services/navigation_service.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'auth_screen.dart';
import 'model/user_model.dart';

class HomeScreen extends StatelessWidget {
  final UserModel user;
  const HomeScreen({super.key, required this.user});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text(
          'Home',
          style: TextStyle(color: Colors.white),
        ),
        actions: [
          ElevatedButton.icon(
            onPressed: () async {
              await logout();
              Navigator.of(context).pushAndRemoveUntil(
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
                'Hello ${user.username}! This is your smart wallet address:',
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
                      user.contractId,
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
                    onPressed: () => _copyToClipboard(user.contractId),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              const Text(
                'You can now connect to your wallet',
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: Colors.deepPurple,
                ),
              ),
              const SizedBox(height: 60),
              ElevatedButton.icon(
                onPressed: () async {
                  await logout();
                },
                icon: const Icon(Icons.how_to_vote),
                label: const Text('Try it now!'),
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

  static Future<void> logout() async {
    var prefs = await SharedPreferences.getInstance();
    prefs.remove('sp:contractId');
    prefs.remove('sp:credentialsId');
    prefs.remove('sp:username');
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
