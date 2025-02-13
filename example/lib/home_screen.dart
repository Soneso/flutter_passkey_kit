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
  bool isAddingEd25519Signer = false;
  bool isEd25519Transferring = false;

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
                size: 10,
              ),
              const SizedBox(height: 20),
              const Text(
                'You are connected to your wallet!',
                style: TextStyle(
                  fontSize: 20,
                  fontWeight: FontWeight.bold,
                  color: Colors.deepPurple,
                ),
              ),
              const SizedBox(height: 16),
              _contractIdRow(),
              const SizedBox(height: 16),
              _balanceRow(),
              const SizedBox(height: 16),
              _ed25519AddRow(),
              const SizedBox(height: 16),
              _ed25519TransferRow(),
            ],
          ),
        ),
      ),
    );
  }

  void _ed25519Transfer() async {
    setState(() {
      isEd25519Transferring = true;
    });
    try {

      final transaction = await StellarService.buildEd25519TransferTx(widget.user.contractId);

      final signerKeypair = KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret());

      final signaturesExpirationLedger =
          await StellarService.getLatestLedgerSequence() + 60;


      await widget.kit.signTxAuthEntriesWithKeyPair(transaction,
          signerKeypair: signerKeypair,
          signaturesExpirationLedger: signaturesExpirationLedger);

      final simulateResponse =
      await StellarService.simulateSorobanTx(transaction);
      if (simulateResponse.resultError != null) {
        throw Exception(
            "could not simulate signed transaction: ${simulateResponse.resultError!}");
      }

      transaction.sorobanTransactionData = simulateResponse.transactionData;
      transaction.addResourceFee(simulateResponse.minResourceFee!);
      transaction.setSorobanAuth(simulateResponse.sorobanAuth);
      transaction.sign(StellarService.submitterKeyPair, StellarService.network);

      await StellarService.sendAndCheckSorobanTx(transaction);

      _showMsg("Transfer success!");
      _refreshBalance();
    } catch (e) {
      _showErrMsg('Error: $e');
      log('Error: $e');
    } finally {
      setState(() {
        isEd25519Transferring = false;
      });
    }
  }

  void _addEd25519Signer() async {
    setState(() {
      isAddingEd25519Signer = true;
    });
    try {
      final signerPublicKey =
          KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret()).accountId;

      var transaction = await widget.kit.addEd25519(
          StellarService.submitterKeyPair.accountId, signerPublicKey,
          storage: PasskeySignerStorage.temporary);

      final signaturesExpirationLedger =
          await StellarService.getLatestLedgerSequence() + 60;
      await widget.kit.signTxAuthEntriesWithPasskey(transaction,
          getPasskeyCredentials: AuthService.getPasskeyCredentials,
          signaturesExpirationLedger: signaturesExpirationLedger);

      final simulateResponse =
          await StellarService.simulateSorobanTx(transaction);
      if (simulateResponse.resultError != null) {
        throw Exception(
            "could not simulate signed transaction: ${simulateResponse.resultError!}");
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
        isAddingEd25519Signer = false;
      });
    }
  }

  Row _contractIdRow() {
    return Row(
      children: [
        Expanded(
          flex: 7,
          child: Text(
            widget.user.contractId,
            style: const TextStyle(
              fontSize: 16,
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
    );
  }
  Row _balanceRow() {
    return Row(
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
    );
  }

  Row _ed25519AddRow() {
    return Row(
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
          icon: isAddingEd25519Signer
              ? const SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.blue),
              strokeWidth: 2,
            ),
          )
              : const Icon(
            Icons.add,
            size: 20,
          ),
          onPressed: () => isAddingEd25519Signer ? null : _addEd25519Signer(),
        ),
      ],
    );
  }

  Row _ed25519TransferRow() {
    return Row(
      children: [
        const Expanded(
          flex: 7,
          child: Text(
            "Ed25519 Transfer",
            style: TextStyle(
              fontSize: 20,
              fontWeight: FontWeight.bold,
              color: Colors.blue,
            ),
          ),
        ),
        IconButton(
          icon: isEd25519Transferring
              ? const SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(
              valueColor: AlwaysStoppedAnimation<Color>(Colors.blue),
              strokeWidth: 2,
            ),
          )
              : const Icon(
            Icons.arrow_forward,
            size: 20,
          ),
          onPressed: () => isEd25519Transferring ? null : _ed25519Transfer(),
        ),
      ],
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
}
