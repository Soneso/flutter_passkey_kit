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
  bool isFundingWallet = false;
  bool isLoadingBalance = false;
  bool isAddingEd25519Signer = false;
  bool isAddingPolicy = false;
  bool isAddingSecp256r1Signer = false;
  bool isEd25519Transferring = false;
  bool isPolicyTransferring = false;
  bool isMultisigTransferring = false;

  String? keyName;

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
      body: SingleChildScrollView(
        child: Center(
          child: Padding(
            padding: const EdgeInsets.all(16.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.start,
              children: <Widget>[
                const Text(
                  'You are connected to your wallet!',
                  style: TextStyle(
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Colors.deepPurple,
                  ),
                ),
                const Divider(),
                const SizedBox(height: 25),
                _contractIdRow(),
                const SizedBox(height: 5),
                _balanceRow(),
                const Divider(),
                _fundWalletRow(),
                const Divider(),
                _ed25519AddRow(),
                const SizedBox(height: 5),
                _ed25519TransferRow(),
                const Divider(),
                _policyAddRow(),
                _policyTransferRow(),
                const Divider(),
                _multisigTransferRow(),
                const Divider(),
                _secp256r1AddRow(),
                _secp256r1AddLabelRow(),
                const Divider(),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _fundWallet() async {
    setState(() {
      isFundingWallet = true;
    });
    try {
      await StellarService.fundWallet(widget.user.contractId);
      _refreshBalance();
    } catch (e) {
      _showErrMsg('Error: $e');
      log('Error: $e');
    } finally {
      setState(() {
        isFundingWallet = false;
      });
    }
  }

  void _addEd25519Signer() async {
    setState(() {
      isAddingEd25519Signer = true;
    });
    try {
      final signerAccountId =
          KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret()).accountId;

      // You can restrict the signer by adding policy limits here.
      /*Map<Address, List<PasskeySignerKey>?> limits = {
        Address.forContractId(EnvService.getNativeSacCId()): [
          PolicyPasskeySignerKey(
              Address.forContractId(EnvService.getSamplePolicyCId()))
        ]
      };*/

      var transaction = await widget.kit.addEd25519(
          StellarService.submitterKeyPair.accountId, signerAccountId,
          // limits:limits,    // without limits
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

  void _ed25519Transfer() async {
    setState(() {
      isEd25519Transferring = true;
    });
    try {
      final transaction = await StellarService.buildTransferTx(
          widget.user.contractId,
          lumens: 2);

      final signerKeypair =
      KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret());

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

  void _addPolicy() async {
    setState(() {
      isAddingPolicy = true;
    });
    try {
      final signerAccountKp =
          KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret());

      Map<Address, List<PasskeySignerKey>?> limits = {
        Address.forContractId(EnvService.getSamplePolicyCId()): [
          Ed25519PasskeySignerKey(signerAccountKp.publicKey)
        ]
      };

      var transaction = await widget.kit.addPolicy(
          StellarService.submitterKeyPair.accountId,
          Address.forContractId(EnvService.getSamplePolicyCId()),
          limits: limits,
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

      _showMsg("Policy added.");
    } catch (e) {
      _showErrMsg('Error: $e');
      log('Error: $e');
    } finally {
      setState(() {
        isAddingPolicy = false;
      });
    }
  }

  void _policyTransfer() async {
    setState(() {
      isPolicyTransferring = true;
    });
    try {
      final transaction =
          await StellarService.buildTransferTx(widget.user.contractId, lumens: 1);

      final signerKeypair =
          KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret());

      final signaturesExpirationLedger =
          await StellarService.getLatestLedgerSequence() + 60;

      await widget.kit.signTxAuthEntriesWithPolicy(transaction,
          policyContractId: EnvService.getSamplePolicyCId(),
          signaturesExpirationLedger: signaturesExpirationLedger);

      await widget.kit.signTxAuthEntriesWithKeyPair(transaction,
          signerKeypair: signerKeypair);

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
        isPolicyTransferring = false;
      });
    }
  }


  void _multisigTransfer() async {
    setState(() {
      isMultisigTransferring = true;
    });
    try {
      final transaction =
      await StellarService.buildTransferTx(widget.user.contractId, lumens: 1);

      final signerKeypair =
      KeyPair.fromSecretSeed(EnvService.getEd25519SignerSecret());

      final signaturesExpirationLedger =
          await StellarService.getLatestLedgerSequence() + 60;

      await widget.kit.signTxAuthEntriesWithPolicy(transaction,
          policyContractId: EnvService.getSamplePolicyCId(),
          signaturesExpirationLedger: signaturesExpirationLedger);

      await widget.kit.signTxAuthEntriesWithKeyPair(transaction,
          signerKeypair: signerKeypair);

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

      _showMsg("Transfer success!");
      _refreshBalance();
    } catch (e) {
      _showErrMsg('Error: $e');
      log('Error: $e');
    } finally {
      setState(() {
        isMultisigTransferring = false;
      });
    }
  }

  void _addSecp256r1Signer() async {
    if (keyName == null) {
      _showErrMsg('Please enter a name for the signer');
      return;
    }
    setState(() {
      isAddingSecp256r1Signer = true;
    });
    try {
      final createKeyResponse = await widget.kit.createKey(
          EnvService.getAppName(),
          keyName!,
          AuthService.createPasskeyCredentials);

      final sequence = await StellarService.getLatestLedgerSequence();

      var transaction = await widget.kit.addSecp256r1(
          StellarService.submitterKeyPair.accountId,
          createKeyResponse.keyId,
          createKeyResponse.publicKey,
          storage: PasskeySignerStorage.temporary,
          expiration: sequence + 518400);

      final signaturesExpirationLedger = sequence + 60;
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
        isAddingSecp256r1Signer = false;
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
        _rowLabel(
            "Balance: ${isLoadingBalance ? 'loading ...' : (balance == null ? 'press refresh to load' : '$balance XLM')}"),
        IconButton(
          icon: isLoadingBalance
              ? _loadingIndicator()
              : const Icon(
                  Icons.refresh_outlined,
                  size: 20,
                ),
          onPressed: () => isLoadingBalance ? null : _refreshBalance(),
        ),
      ],
    );
  }

  Row _fundWalletRow() {
    return Row(
      children: [
        _rowLabel("Add Funds (testnet only)"),
        IconButton(
          icon: isFundingWallet
              ? _loadingIndicator()
              : const Icon(
                  Icons.add,
                  size: 20,
                ),
          onPressed: () => isFundingWallet ? null : _fundWallet(),
        ),
      ],
    );
  }

  Row _ed25519AddRow() {
    return Row(
      children: [
        _rowLabel("Add Ed25519 Signer"),
        IconButton(
          icon: isAddingEd25519Signer
              ? _loadingIndicator()
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
        _rowLabel("Ed25519 Transfer"),
        IconButton(
          icon: isEd25519Transferring
              ? _loadingIndicator()
              : const Icon(
                  Icons.arrow_forward,
                  size: 20,
                ),
          onPressed: () => isEd25519Transferring ? null : _ed25519Transfer(),
        ),
      ],
    );
  }

  Row _policyAddRow() {
    return Row(
      children: [
        _rowLabel("Add Policy"),
        IconButton(
          icon: isAddingPolicy
              ? _loadingIndicator()
              : const Icon(
                  Icons.add,
                  size: 20,
                ),
          onPressed: () => isAddingPolicy ? null : _addPolicy(),
        ),
      ],
    );
  }

  Row _policyTransferRow() {
    return Row(
      children: [
        _rowLabel("Policy Transfer"),
        IconButton(
          icon: isPolicyTransferring
              ? _loadingIndicator()
              : const Icon(
                  Icons.arrow_forward,
                  size: 20,
                ),
          onPressed: () => isPolicyTransferring ? null : _policyTransfer(),
        ),
      ],
    );
  }

  Row _multisigTransferRow() {
    return Row(
      children: [
        _rowLabel("Multisig Transfer"),
        IconButton(
          icon: isMultisigTransferring
              ? _loadingIndicator()
              : const Icon(
            Icons.arrow_forward,
            size: 20,
          ),
          onPressed: () => isMultisigTransferring ? null : _multisigTransfer(),
        ),
      ],
    );
  }

  Row _secp256r1AddLabelRow() {
    return Row(
      children: [
        _rowLabel("Add Secp256r1 Signer"),
        IconButton(
          icon: isAddingSecp256r1Signer
              ? _loadingIndicator()
              : const Icon(
                  Icons.add,
                  size: 20,
                ),
          onPressed: () =>
              isAddingSecp256r1Signer ? null : _addSecp256r1Signer(),
        ),
      ],
    );
  }

  Row _secp256r1AddRow() {
    return Row(
      children: [
        Expanded(
          flex: 7,
          child: TextField(
            onChanged: (value) {
              setState(() {
                keyName = value;
              });
            },
            decoration: const InputDecoration(
              hintText: 'New Secp256r1 Signer name',
              border: OutlineInputBorder(),
              prefixIcon: Icon(Icons.person, color: Colors.deepPurple),
            ),
          ),
        ),
      ],
    );
  }

  Widget _rowLabel(String text) {
    return Expanded(
      flex: 7,
      child: Text(
        text,
        style: const TextStyle(
          fontSize: 16,
          fontWeight: FontWeight.bold,
          color: Colors.blue,
        ),
      ),
    );
  }

  Widget _loadingIndicator() {
    return const SizedBox(
      width: 24,
      height: 24,
      child: CircularProgressIndicator(
        valueColor: AlwaysStoppedAnimation<Color>(Colors.blue),
        strokeWidth: 2,
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
}
