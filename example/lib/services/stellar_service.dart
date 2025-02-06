import 'package:example/services/env_service.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

class StellarService {

  static Future<SubmitTransactionResponse> feeBump(Transaction innerTx) async {
    var submitterKeyPair =
        KeyPair.fromSecretSeed(EnvService.getSubmitterSecret());
    var submitterAccountId = submitterKeyPair.accountId;
    FeeBumpTransaction feeBump = FeeBumpTransactionBuilder(innerTx)
        .setBaseFee(innerTx.fee + 100)
        .setFeeAccount(submitterAccountId)
        .build();
    feeBump.sign(submitterKeyPair, EnvService.getNetwork());
    StellarSDK sdk = StellarSDK(EnvService.getHorizonUrl());
    return await sdk.submitFeeBumpTransaction(feeBump);
  }
}
