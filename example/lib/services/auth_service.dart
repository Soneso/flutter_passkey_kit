import 'package:credential_manager/credential_manager.dart' as cd;
import 'package:flutter_passkey_kit/flutter_passkey_kit.dart';

class AuthService {
  static cd.CredentialManager credentialManager = cd.CredentialManager();

  static Future<PublicKeyCredential> createPasskeyCredentials(
      {required CredentialCreationOptions options}) async {
    final savedCredentials = await credentialManager.savePasskeyCredentials(
        request: cd.CredentialCreationOptions.fromJson(options.toJson()));
    return PublicKeyCredential.fromJson(savedCredentials.toJson());
  }

  static Future<PublicKeyCredential> getPasskeyCredentials(
      {required CredentialLoginOptions options}) async {
    final credResponse = await credentialManager.getCredentials(
      passKeyOption: cd.CredentialLoginOptions.fromJson(options.toJson()),
      fetchOptions: cd.FetchOptionsAndroid(passKey: true),
    );

    if (credResponse.publicKeyCredential == null) {
      throw Exception(
          'Invalid passkey login response: publicKeyCredential not found');
    }

    return PublicKeyCredential.fromJson(
        credResponse.publicKeyCredential!.toJson());
  }
}
