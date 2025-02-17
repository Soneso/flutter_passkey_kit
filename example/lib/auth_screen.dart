import 'dart:developer';
import 'package:credential_manager/credential_manager.dart' as cd;
import 'package:example/services/auth_service.dart';
import 'package:example/services/env_service.dart';
import 'package:example/services/stellar_service.dart';
import 'package:example/wallet_created_screen.dart';
import 'package:flutter/material.dart';
import 'package:flutter_passkey_kit/flutter_passkey_kit.dart';
import 'model/user_model.dart';
import 'services/navigation_service.dart';
import 'home_screen.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  String? username;
  bool isCreatingWallet = false;
  bool isConnectingWallet = false;
  String? errorMessage;
  PasskeyKit? passkeyKit;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(EnvService.getAppName(),
            style: const TextStyle(color: Colors.white)),
        backgroundColor: Colors.deepPurple,
      ),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(16.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: <Widget>[
              const Text(
                'Welcome to the flutter passkey key demo',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 16, color: Colors.deepPurple),
              ),
              const SizedBox(height: 20),
              ElevatedButton.icon(
                onPressed: isConnectingWallet ? null : connectWallet,
                icon: isConnectingWallet
                    ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(
                    valueColor:
                    AlwaysStoppedAnimation<Color>(Colors.white),
                    strokeWidth: 2,
                  ),
                )
                    : const Icon(Icons.login),
                label:
                isConnectingWallet ? const SizedBox.shrink() : const Text('Connect Wallet'),
                style: ElevatedButton.styleFrom(
                  foregroundColor: Colors.white,
                  backgroundColor: Colors.deepPurple,
                  padding: const EdgeInsets.symmetric(
                      vertical: 12.0, horizontal: 24.0),
                  textStyle: const TextStyle(fontSize: 16.0),
                ),
              ),
              const SizedBox(height: 24),
              const Text(
                'Or enter a username to create a new one:',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 16, color: Colors.deepPurple),
              ),
              const SizedBox(height: 10),
              TextField(
                onChanged: (value) {
                  setState(() {
                    username = value;
                    errorMessage = null;
                  });
                },
                decoration: const InputDecoration(
                  hintText: 'Username for new wallet',
                  border: OutlineInputBorder(),
                  prefixIcon: Icon(Icons.person, color: Colors.deepPurple),
                ),
              ),
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: isCreatingWallet ? null : createWallet,
                icon: isCreatingWallet
                    ? const SizedBox(
                  width: 24,
                  height: 24,
                  child: CircularProgressIndicator(
                    valueColor:
                    AlwaysStoppedAnimation<Color>(Colors.white),
                    strokeWidth: 2,
                  ),
                )
                    : const Icon(Icons.person_add),
                label: isCreatingWallet
                    ? const SizedBox.shrink()
                    : const Text('Create new Wallet'),
                style: ElevatedButton.styleFrom(
                  foregroundColor: Colors.white,
                  backgroundColor: Colors.deepPurple,
                  padding: const EdgeInsets.symmetric(
                      vertical: 12.0, horizontal: 24.0),
                  textStyle: const TextStyle(fontSize: 16.0),
                ),
              ),
              const SizedBox(height: 16),
              if (errorMessage != null)
                Align(
                  alignment: Alignment.centerLeft,
                  child: Padding(
                    padding: const EdgeInsets.only(bottom: 8.0),
                    child: Text(
                      errorMessage!,
                      style: const TextStyle(color: Colors.red),
                    ),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }


  Future<void> createWallet() async {
    if (username == null || username?.isEmpty == true) {
      setState(() {
        errorMessage = 'Please enter a username';
      });
      return;
    }

    // start registration
    setState(() {
      isCreatingWallet = true;
      errorMessage = null;
    });

    try {
      final kit = _getPasskeyKit();
      var result = await kit.createWallet(EnvService.getAppName(), username!,
          AuthService.createPasskeyCredentials);
      var user = UserModel(
          username: username!,
          credentialsId: result.keyId,
          contractId: result.contractId);

      await user.save();

      // submit to stellar
      var response = await StellarService.feeBump(result.transaction);
      if (!response.success) {
        throw Exception("Error submitting transaction to stellar");
      }
      log("Wallet created: ${user.contractId}");

      Navigator.of(NavigationService.navigatorKey.currentContext!).pushReplacement(
        MaterialPageRoute(
          builder: (context) => WalletCreatedScreen(
            user: user,
          ),
        ),
      );
    } on cd.CredentialException catch (e) {
      log("Error: ${e.message} ${e.code} ${e.details} ");
      setState(() {
        errorMessage = 'Error: ${e.message}';
      });
    } catch (e) {
      setState(() {
        errorMessage = 'Error: $e';
      });
    } finally {
      setState(() {
        isCreatingWallet = false;
      });
    }
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

  Future<void> connectWallet() async {
    setState(() {
      isConnectingWallet = true;
      errorMessage = null;
    });
    try {
      var kit = _getPasskeyKit();
      var result = await kit.connectWallet(getPasskeyCredentials: AuthService.getPasskeyCredentials);

      var user = UserModel(
          username: result.username != null ? result.username! : "Friend" ,
          credentialsId: result.keyId,
          contractId: result.contractId);

      await user.save();

      Navigator.of(NavigationService.navigatorKey.currentContext!).pushReplacement(
        MaterialPageRoute(
          builder: (context) => HomeScreen(
            user: user,
            kit: kit,
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
}
