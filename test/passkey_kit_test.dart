import 'package:flutter_test/flutter_test.dart';
import 'dart:typed_data';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

void main() {
  test('keypair', () {
    var network = Network.PUBLIC;
    var kp = KeyPair.fromSecretSeedList(Util.hash(Uint8List.fromList(network.networkPassphrase.codeUnits)));
    print(kp.accountId);
  });


}
