import 'package:example/services/env_service.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

class StellarService {

  static final sorobanServer = SorobanServer(EnvService.getRpcUrl());
  static final stellarSDK = StellarSDK(EnvService.getHorizonUrl());
  static final network = EnvService.getNetwork();
  static final submitterKeyPair = KeyPair.fromSecretSeed(EnvService.getSubmitterSecret());
  static final nativeSacCId = EnvService.getNativeSacCId();

  static Future<SubmitTransactionResponse> feeBump(Transaction innerTx) async {
    var submitterAccountId = submitterKeyPair.accountId;
    FeeBumpTransaction feeBump = FeeBumpTransactionBuilder(innerTx)
        .setBaseFee(innerTx.fee + 100)
        .setFeeAccount(submitterAccountId)
        .build();
    feeBump.sign(submitterKeyPair, network);
    return await stellarSDK.submitFeeBumpTransaction(feeBump);
  }

  static Future<void> fundWallet(String contractId) async {

    final from = Address.forAccountId(submitterKeyPair.accountId).toXdrSCVal();
    final to = Address.forContractId(contractId).toXdrSCVal();
    final amount = XdrSCVal.forI128Parts(0, 10 * 10000000); // 10 XLM
    final function = InvokeContractHostFunction(nativeSacCId, "transfer", arguments: [from, to, amount]);
    await  _invokeSorobanFunction(function);
  }

  static Future<double> getBalance(String contractId) async {

    final function = InvokeContractHostFunction(nativeSacCId, "balance",
        arguments: [Address.forContractId(contractId).toXdrSCVal()]);

    final response = await  _invokeSorobanFunction(function);
    final resVal = response.getResultValue();
    if (resVal != null && resVal.i128 != null) {
      return (resVal.i128!.lo.uint64 / 10000000);
    }
    throw Exception("Could not get balance for $contractId: no result or unknown result");
  }

  static Future<GetTransactionResponse> _invokeSorobanFunction(InvokeContractHostFunction function) async {
    final submitterAccountId = submitterKeyPair.accountId;
    final submitterAccount = await stellarSDK.accounts.account(submitterAccountId);
    final operation = InvokeHostFuncOpBuilder(function).build();
    final transaction = TransactionBuilder(submitterAccount).addOperation(operation).build();
    final request = SimulateTransactionRequest(transaction);
    final simulateResponse = await sorobanServer.simulateTransaction(request);
    if (simulateResponse.resultError != null) {
      throw Exception("Could not simulate transaction");
    }
    transaction.sorobanTransactionData = simulateResponse.transactionData;
    transaction.addResourceFee(simulateResponse.minResourceFee!);
    transaction.setSorobanAuth(simulateResponse.sorobanAuth);
    transaction.sign(submitterKeyPair, network);
    final sendResponse = await sorobanServer.sendTransaction(transaction);
    if (sendResponse.hash == null) {
      throw Exception("Error sending tx to soroban: no transaction hash in response");
    }

    final txResponse = await _pollTxStatus(sendResponse.hash!);
    if (GetTransactionResponse.STATUS_SUCCESS != txResponse.status) {
      throw Exception("Error sending tx to soroban: tx not success");
    }
    return txResponse;
  }

  // poll until success or error
  static Future<GetTransactionResponse> _pollTxStatus(String transactionId) async {
    var status = GetTransactionResponse.STATUS_NOT_FOUND;
    GetTransactionResponse? transactionResponse;
    while (status == GetTransactionResponse.STATUS_NOT_FOUND) {
      await Future.delayed(const Duration(seconds: 3), () {});
      transactionResponse = await sorobanServer.getTransaction(transactionId);
      assert(transactionResponse.error == null);
      status = transactionResponse.status!;
      if (status == GetTransactionResponse.STATUS_FAILED) {
        assert(transactionResponse.resultXdr != null);
        assert(false);
      } else if (status == GetTransactionResponse.STATUS_SUCCESS) {
        assert(transactionResponse.resultXdr != null);
      }
    }
    return transactionResponse!;
  }
}
