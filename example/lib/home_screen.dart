import 'package:clipboard/clipboard.dart';
import 'package:example/services/navigation_service.dart';
import 'package:example/services/stellar_service.dart';
import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'auth_screen.dart';
import 'model/user_model.dart';

class HomeScreen extends StatefulWidget {
  final UserModel user;
  const HomeScreen({super.key, required this.user});

  @override
  State<HomeScreen> createState() => _HomeScreenState();

  static Future<void> logout() async {
    var prefs = await SharedPreferences.getInstance();
    prefs.remove('sp:contractId');
    prefs.remove('sp:credentialsId');
    prefs.remove('sp:username');
  }
}

class _HomeScreenState extends State<HomeScreen> {
  double? balance;

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
              await HomeScreen.logout();
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
                Icons.check,
                color: Colors.green,
                size: 100,
              ),
              const SizedBox(height: 40),
              Text(
                'Hello ${widget.user.username}! You are connected to your wallet!',
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
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    flex: 7,
                    child: Text(
                      "Balance: ${balance == null ? "press refresh to load" : '$balance XLM'}",
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: const Icon(
                      Icons.refresh_outlined,
                      size: 20,
                    ),
                    onPressed: () => _refreshBalance(),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _copyToClipboard(String text) async {
    await FlutterClipboard.copy(text);
    _showCopied();
  }

  void _refreshBalance() async {
    var res = await StellarService.getBalance(widget.user.contractId);
    setState(() {
      balance = res;
    });
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
