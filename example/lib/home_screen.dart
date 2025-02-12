import 'package:clipboard/clipboard.dart';
import 'package:example/services/auth_service.dart';
import 'package:example/services/env_service.dart';
import 'package:example/services/navigation_service.dart';
import 'package:example/services/stellar_service.dart';
import 'package:flutter/material.dart';
import 'package:flutter_passkey_kit/flutter_passkey_kit.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';
import 'dart:developer';
import 'auth_screen.dart';
import 'model/user_model.dart';

class HomeScreen extends StatefulWidget {
  final UserModel user;
  final PasskeyKit kit;
  const HomeScreen({super.key, required this.user, required this.kit});

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
  bool isLoadingBalance = false;
  bool isAddingSigner = false;

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
              Navigator.of(NavigationService.navigatorKey.currentContext!)
                  .pushAndRemoveUntil(
                      MaterialPageRoute(
                          builder: (builder) =>
                              const AuthScreen(key: Key('auth_screen'))),
                      (predicate) => false);
            },
            label: const Text('Logout'),
            style: ElevatedButton.styleFrom(
              foregroundColor: Colors.white,
              backgroundColor: Colors.deepPurple,
              padding:
                  const EdgeInsets.symmetric(vertical: 12.0, horizontal: 24.0),
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
                size: 50,
              ),
              const SizedBox(height: 40),
              const Text(
                'You are connected to your wallet!',
                style: TextStyle(
                  fontSize: 20,
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
                      "Balance: ${isLoadingBalance ? 'loading ...' : (balance == null ? 'press refresh to load' : '$balance XLM')}",
                      style: const TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: isLoadingBalance
                        ? const SizedBox(
                            width: 24,
                            height: 24,
                            child: CircularProgressIndicator(
                              valueColor:
                                  AlwaysStoppedAnimation<Color>(Colors.blue),
                              strokeWidth: 2,
                            ),
                          )
                        : const Icon(
                            Icons.refresh_outlined,
                            size: 20,
                          ),
                    onPressed: () =>
                        isLoadingBalance ? null : _refreshBalance(),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  const Expanded(
                    flex: 7,
                    child: Text(
                      "Add Ed25519 Signer",
                      style: TextStyle(
                        fontSize: 20,
                        fontWeight: FontWeight.bold,
                        color: Colors.blue,
                      ),
                    ),
                  ),
                  IconButton(
                    icon: isAddingSigner
                        ? const SizedBox(
                      width: 24,
                      height: 24,
                      child: CircularProgressIndicator(
                        valueColor:
                        AlwaysStoppedAnimation<Color>(Colors.blue),
                        strokeWidth: 2,
                      ),
                    )
                        : const Icon(
                      Icons.add,
                      size: 20,
                    ),
                    onPressed: () =>
                    isAddingSigner ? null : _addEd25519Signer(),
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
    _showMsg('Copied to clipboard');
  }

  void _refreshBalance() async {
    setState(() {
      isLoadingBalance = true;
    });
    var res = await StellarService.getBalance(widget.user.contractId);
    setState(() {
      balance = res;
      isLoadingBalance = false;
    });
  }

  void _showMsg(String text) {
    ScaffoldMessenger.of(NavigationService.navigatorKey.currentContext!)
        .showSnackBar(
       SnackBar(
        content: Text(text),
        backgroundColor: Colors.green,
      ),
    );
  }

  void _showErrMsg(String text) {
    ScaffoldMessenger.of(NavigationService.navigatorKey.currentContext!)
        .showSnackBar(
      SnackBar(
        content: Text(text),
        backgroundColor: Colors.red,
      ),
    );
  }

  void _addEd25519Signer() async {
    setState(() {
      isAddingSigner = true;
    });
    try {

      final signerPublicKey = KeyPair
          .fromSecretSeed(EnvService.getEd25519SignerSecret())
          .accountId;

      var transaction = await widget.kit.addEd25519(
          StellarService.submitterKeyPair.accountId,
          signerPublicKey,
          storage: PasskeySignerStorage.temporary);

      final signaturesExpirationLedger = await StellarService.getLatestLedgerSequence() + 60;
      await widget.kit.signTxAuthEntries(transaction,
          getPasskeyCredentials: AuthService.getPasskeyCredentials,
          signaturesExpirationLedger: signaturesExpirationLedger);


      final simulateResponse = await StellarService.simulateSorobanTx(transaction);
      if (simulateResponse.resultError != null) {
        throw Exception("could not simulate signed transaction: ${simulateResponse.resultError!}");
      }

      transaction.sorobanTransactionData = simulateResponse.transactionData;
      transaction.addResourceFee(simulateResponse.minResourceFee!);
      transaction.setSorobanAuth(simulateResponse.sorobanAuth);
      transaction.sign(StellarService.submitterKeyPair, StellarService.network);

      await StellarService.sendAndCheckSorobanTx(transaction);

      _showMsg("Signer added!");
    } catch (e) {
      _showErrMsg('Error: $e');
      log('Error: $e');
    } finally {
      setState(() {
        isAddingSigner = false;
      });
    }
  }
}
