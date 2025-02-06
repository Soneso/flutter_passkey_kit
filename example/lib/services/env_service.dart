import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

class EnvService {

  static String getRpId() {
    return getValue('rp_id');
  }

  static String getRpcUrl() {
    return getValue('rpc_url');
  }

  static String getWasmHash() {
    return getValue('wallet_wasm_hash');
  }

  static String getAppName() {
    return getValue('app_name');
  }

  static String getHorizonUrl() {
    return getValue('horizon_url');
  }

  static Network getNetwork() {
    return Network(getValue('network_passphrase'));
  }

  static String getSubmitterSecret() {
    final value = dotenv.env['submitter_secret'];
    if (value == null) {
      throw Exception(".env file must contain submitter_secret");
    }
    return value;
  }

  static String getValue(String key) {
    final value = dotenv.env[key];
    if (value == null) {
      throw Exception(".env file must contain $key");
    }
    return value;
  }

  static String? getValueOrNull(String key) {
    return dotenv.env[key];
  }


}