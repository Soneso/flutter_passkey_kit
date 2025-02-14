import 'package:example/services/env_service.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

class StellarService {
  static final sorobanServer = SorobanServer(EnvService.getRpcUrl());
  static final stellarSDK = StellarSDK(EnvService.getHorizonUrl());
  static final network = EnvService.getNetwork();
  static final submitterKeyPair =
      KeyPair.fromSecretSeed(EnvService.getSubmitterSecret());
  static final nativeSacCId = EnvService.getNativeSacCId();

  static Future<SubmitTransactionResponse> feeBump(Transaction innerTx) async {
    var submitterAccountId = submitterKeyPair.accountId;
    FeeBumpTransaction feeBump = FeeBumpTransactionBuilder(innerTx)
        .setBaseFee(innerTx.fee + 1000)
        .setFeeAccount(submitterAccountId)
        .build();
    feeBump.sign(submitterKeyPair, network);
    return await stellarSDK.submitFeeBumpTransaction(feeBump);
  }

  static Future<int> getLatestLedgerSequence() async {
    return (await sorobanServer.getLatestLedger()).sequence!;
  }

  static Future<SimulateTransactionResponse> simulateSorobanTx(
      Transaction tx) async {
    return await sorobanServer
        .simulateTransaction(SimulateTransactionRequest(tx));
  }

  static Future<void> fundWallet(String contractId) async {
    if (network.networkPassphrase != 'Test SDF Network ; September 2015') {
      throw Exception(
          'Only testnet wallets can be funded by the app. Transfer XLM to your wallet address to fund it.');
    }
    final randomKeyPair = KeyPair.random();
    await FriendBot.fundTestAccount(randomKeyPair.accountId);
    final from = Address.forAccountId(randomKeyPair.accountId).toXdrSCVal();
    final to = Address.forContractId(contractId).toXdrSCVal();
    final amount = XdrSCVal.forI128Parts(0, 9900 * 10000000); // 9900 XLM
    final function = InvokeContractHostFunction(nativeSacCId, "transfer",
        arguments: [from, to, amount]);
    await _invokeSorobanFunction(function,
        txSourceAccountKeyPair: randomKeyPair);
  }

  static Future<double> getBalance(String contractId) async {
    final function = InvokeContractHostFunction(nativeSacCId, "balance",
        arguments: [Address.forContractId(contractId).toXdrSCVal()]);

    final response = await _invokeSorobanFunction(function);
    final resVal = response.getResultValue();
    if (resVal != null && resVal.i128 != null) {
      return (resVal.i128!.lo.uint64 / 10000000);
    }
    throw Exception(
        "Could not get balance for $contractId: no result or unknown result");
  }

  static Future<GetTransactionResponse> _invokeSorobanFunction(
      InvokeContractHostFunction function,
      {KeyPair? txSourceAccountKeyPair}) async {
    final sourceAndSignKeyPair = txSourceAccountKeyPair ?? submitterKeyPair;
    final submitterAccountId = sourceAndSignKeyPair.accountId;
    final submitterAccount =
        await stellarSDK.accounts.account(submitterAccountId);
    final operation = InvokeHostFuncOpBuilder(function).build();
    final transaction =
        TransactionBuilder(submitterAccount).addOperation(operation).build();
    final request = SimulateTransactionRequest(transaction);
    final simulateResponse = await sorobanServer.simulateTransaction(request);
    if (simulateResponse.resultError != null) {
      throw Exception("Could not simulate transaction");
    }
    transaction.sorobanTransactionData = simulateResponse.transactionData;
    transaction.addResourceFee(simulateResponse.minResourceFee!);
    transaction.setSorobanAuth(simulateResponse.sorobanAuth);
    transaction.sign(sourceAndSignKeyPair, network);
    return await sendAndCheckSorobanTx(transaction);
  }

  static Future<GetTransactionResponse> sendAndCheckSorobanTx(
      Transaction tx) async {
    final sendResponse = await sorobanServer.sendTransaction(tx);
    if (sendResponse.status == SendTransactionResponse.STATUS_ERROR ||
        sendResponse.hash == null) {
      throw Exception(
          "Error sending tx to soroban: no transaction hash in response");
    }
    final txResponse = await _pollTxStatus(sendResponse.hash!);
    if (GetTransactionResponse.STATUS_SUCCESS != txResponse.status) {
      throw Exception("Error sending tx to soroban: tx not success");
    }
    return txResponse;
  }

  // poll until success or error
  static Future<GetTransactionResponse> _pollTxStatus(
      String transactionId) async {
    var status = GetTransactionResponse.STATUS_NOT_FOUND;
    GetTransactionResponse? transactionResponse;
    while (status == GetTransactionResponse.STATUS_NOT_FOUND) {
      await Future.delayed(const Duration(seconds: 3), () {});
      transactionResponse = await sorobanServer.getTransaction(transactionId);
      status = transactionResponse.status!;
    }
    return transactionResponse!;
  }

  static Future<Transaction> buildTransferTx(String contractId, {int lumens = 1}) async {
    final from = Address.forContractId(contractId).toXdrSCVal();
    final to = Address.forAccountId(submitterKeyPair.accountId).toXdrSCVal();
    final amount = XdrSCVal.forI128Parts(0, lumens * 10000000); // 1 XLM
    final function = InvokeContractHostFunction(nativeSacCId, "transfer",
        arguments: [from, to, amount]);
    final sourceAccountId = submitterKeyPair.accountId;
    final sourceAccount = await stellarSDK.accounts.account(sourceAccountId);
    final operation = InvokeHostFuncOpBuilder(function).build();
    final transaction =
        TransactionBuilder(sourceAccount).addOperation(operation).build();
    final request = SimulateTransactionRequest(transaction);
    final simulateResponse = await sorobanServer.simulateTransaction(request);
    if (simulateResponse.resultError != null) {
      throw Exception("Could not simulate transaction");
    }

    transaction.sorobanTransactionData = simulateResponse.transactionData;
    transaction.addResourceFee(simulateResponse.minResourceFee!);
    transaction.setSorobanAuth(simulateResponse.sorobanAuth);
    return transaction;
  }
}
