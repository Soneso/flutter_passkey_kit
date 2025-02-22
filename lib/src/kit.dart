import 'dart:convert';
import 'dart:developer' as dev;
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter_passkey_kit/src/auth.dart';
import 'package:stellar_flutter_sdk/stellar_flutter_sdk.dart';

class PasskeyKit {
  String rpId;
  String rpcUrl;
  String walletWasmHash;
  Network network;
  String? keyId;
  late KeyPair walletKeyPair;
  late SorobanServer server;

  static const String _challengeStr = "stellaristhebetterblockchain";
  static final Codec<String, String> _stringToBase64Url = utf8.fuse(base64Url);

  /// Constructor. [rpId] is the domain where your DAL file is deployed.
  /// [rpcUrl] is the url to the soroban rpc server to be used for requests.
  /// [walletWasmHash] is the hash of your installed smart wallet contract.
  /// Please also provide the Stellar [network] to be used.
  PasskeyKit(this.rpId, this.rpcUrl, this.walletWasmHash, this.network) {
    walletKeyPair = KeyPair.fromSecretSeedList(
        Util.hash(Uint8List.fromList(network.networkPassphrase.codeUnits)));
    server = SorobanServer(rpcUrl);
    server.enableLogging = true;
  }

  /// Returns a [CreateWalletResponse] containing the data needed to create a new wallet for the given [appName] and [userName].
  /// This includes the transaction to be submitted by you to the stellar network, so that the wallet is created.
  /// When calling this function you must provide a [createPasskeyCredentials] function that requests the creation and returns the
  /// users passkey credentials. An example can be found in the example folder of this library.
  /// This function will use it's own source account and you will receive an already signed transaction that you
  /// can send to Stellar via a fee bump transaction or to launchtube (https://github.com/stellar/launchtube).
  Future<CreateWalletResponse> createWallet(
      String appName,
      String userName,
      Future<PublicKeyCredential> Function(
              {required CredentialCreationOptions options})
          createPasskeyCredentials) async {
    final createKeyResponse =
        await createKey(appName, userName, createPasskeyCredentials);

    var transaction = await _createAndSignDeployTx(
        keyId: createKeyResponse.keyId,
        publicKey:
            base64Url.decode(base64Url.normalize(createKeyResponse.publicKey)));

    final contractId = _deriveContractId(keyId: createKeyResponse.keyId);

    return CreateWalletResponse(
        createKeyResponse.keyId, contractId, transaction);
  }

  /// This function connects your passkey kit instance to the users wallet if it exists.
  /// If you provide the [keyId] of the user, then this function will only check if the wallet exists
  /// and connect it. If you provide no [keyId] you must provide the [getPasskeyCredentials] function that requests and returns the
  /// users passkey login credentials.
  Future<ConnectWalletResponse> connectWallet(
      {String? keyId,
      Future<PublicKeyCredential> Function(
              {required CredentialLoginOptions options})?
          getPasskeyCredentials}) async {
    String? username;

    if (keyId == null && getPasskeyCredentials == null) {
      throw Exception("KeyId or getPasskeyCredentials must be provided");
    }

    // if no keyId is provided, we must get the users credentials to obtain the id.
    if (keyId == null) {
      var options = CredentialLoginOptions(
        challenge: _stringToBase64Url.encode(_challengeStr),
        rpId: rpId,
        userVerification: "discouraged",
      );

      var credentials = await getPasskeyCredentials!(options: options);
      if (credentials.id == null) {
        throw Exception('Invalid passkey login credentials: id is null');
      }
      keyId = credentials.id;
      var userHandleB64 = credentials.response?.userHandle;
      if (userHandleB64 != null) {
        username =
            _stringToBase64Url.decode(base64Url.normalize(userHandleB64));
      }
    }

    // sign in cannot retrieve a public-key so we can only derive the
    // contract address
    final contractId = _deriveContractId(keyId: keyId!);

    final cData = await server.getContractData(
        contractId,
        XdrSCVal.forLedgerKeyContractInstance(),
        XdrContractDataDurability.PERSISTENT);

    if (cData == null) {
      throw Exception("contract not found: $contractId");
    }

    // connect this instance to the user
    this.keyId = keyId;

    return ConnectWalletResponse(keyId, contractId, username: username);
  }

  /// This function creates a new key, that can be used as a Secp256r1 signer for your wallet.
  /// Provide the [appName] and the [userName] to create the new key for. You must also provide
  /// a [createPasskeyCredentials] function, that requests the creation and returns the
  /// users passkey credentials. An example can be found in the example folder of this library.
  Future<CreateKeyResponse> createKey(
      String appName,
      String userName,
      Future<PublicKeyCredential> Function(
              {required CredentialCreationOptions options})
          createPasskeyCredentials) async {
    final authenticatorSelectionCriteria = AuthenticatorSelectionCriteria(
        requireResidentKey: false,
        residentKey: "preferred",
        userVerification: "discouraged",
        authenticatorAttachment: "platform");

    var now = DateTime.now();
    var random = Random();

    final user = User(
        id: _stringToBase64Url.encode(
            "$userName:${now.millisecondsSinceEpoch}:${random.nextDouble()}"),
        name: userName,
        displayName: "$userName - ${now.toLocal()}");

    final credentialCreationOptions = CredentialCreationOptions(
      challenge: _stringToBase64Url.encode(_challengeStr),
      rp: Rp(name: appName, id: rpId),
      user: user,
      authenticatorSelection: authenticatorSelectionCriteria,
      pubKeyCredParams: [
        PublicKeyCredentialParameters(alg: -7, type: "public-key")
      ],
      attestation: "none",
      excludeCredentials: [],
    );

    final createdCredentials =
        await createPasskeyCredentials(options: credentialCreationOptions);

    if (createdCredentials.id == null) {
      throw Exception("Created credentials have no id");
    }

    final keyId = createdCredentials.id!;

    if (createdCredentials.response == null) {
      return throw Exception(
          "Could not extract attestation response from created credentials");
    }

    final publicKey = getPublicKey(createdCredentials.response!);

    if (publicKey == null) {
      return throw Exception(
          "Could not extract public key from created credentials");
    }

    return CreateKeyResponse(keyId, base64UrlEncode(publicKey.toList()));
  }

  /// Signs a SorobanAuthorizationEntry with passkey credentials. Make sure that the
  /// [entry] has addressCredentials with the expiration ledger sequence correctly set.
  /// Provide [getPasskeyCredentials] so that the user can be asked for their credentials.
  Future<SorobanAuthorizationEntry> signAuthEntryWithPasskey(
      SorobanAuthorizationEntry entry,
      Future<PublicKeyCredential> Function(
              {required CredentialLoginOptions options})
          getPasskeyCredentials) async {
    final payload = _getAuthPayload(entry);

    var options = CredentialLoginOptions(
      challenge: base64UrlEncode(payload.toList()),
      rpId: rpId,
      userVerification: "discouraged",
    );

    var passkeyCredentials = await getPasskeyCredentials(options: options);
    if (passkeyCredentials.id == null) {
      throw Exception('Invalid passkey login credentials: id is null');
    }
    final keyId = passkeyCredentials.id!;

    final passkeySigRawBase64 = passkeyCredentials.response?.signature;
    if (passkeySigRawBase64 == null) {
      throw ArgumentError("Signature not found in credentials result");
    }
    final passkeySignatureRaw =
        base64Url.decode(base64Url.normalize(passkeySigRawBase64));
    final passkeySignature = _compactSignature(passkeySignatureRaw);

    final authenticatorDataB64 = passkeyCredentials.response?.authenticatorData;
    if (authenticatorDataB64 == null) {
      throw ArgumentError("authenticatorData not found in credentials result");
    }
    final authenticatorData =
        base64Url.decode(base64Url.normalize(authenticatorDataB64));

    final clientDataJsonB64 = passkeyCredentials.response?.clientDataJSON;
    if (clientDataJsonB64 == null) {
      throw ArgumentError("clientDataJSON not found in credentials result");
    }
    final clientDataJson =
        base64Url.decode(base64Url.normalize(clientDataJsonB64));

    final scKey =
        Secp256r1PasskeySignerKey(base64Url.decode(base64Url.normalize(keyId)));
    final scVal =
        Secp256r1Signature(authenticatorData, clientDataJson, passkeySignature);
    final scEntry = XdrSCMapEntry(scKey.toXdrSCVal(), scVal.toXdrSCVal());

    _addSignatureToEntry(entry, scEntry);

    return entry;
  }

  /// Signs a SorobanAuthorizationEntry with the [signerKeyPair] as an ed25519 signer. Make sure that the
  /// [entry] has addressCredentials with the expiration ledger sequence correctly set.
  /// Provide [signerKeyPair] including the private key for signing.
  Future<SorobanAuthorizationEntry> signAuthEntryWithKeyPair(
      SorobanAuthorizationEntry entry, KeyPair signerKeyPair) async {
    if (signerKeyPair.privateKey == null) {
      throw Exception("Invalid signer keypair. Must contain private key!");
    }
    final payload = _getAuthPayload(entry);

    final payloadSignature = signerKeyPair.sign(payload);

    final scKey = Ed25519PasskeySignerKey(signerKeyPair.publicKey);
    final scVal = Ed25519Signature(payloadSignature);
    final signature = XdrSCMapEntry(scKey.toXdrSCVal(), scVal.toXdrSCVal());

    _addSignatureToEntry(entry, signature);

    return entry;
  }

  /// Signs a SorobanAuthorizationEntry with the [policyContractId] as a policy signer. Make sure that the
  /// [entry] has addressCredentials with the expiration ledger sequence correctly set.
  Future<SorobanAuthorizationEntry> signAuthEntryWithPolicy(
      SorobanAuthorizationEntry entry, String policyContractId) async {
    final scKey =
        PolicyPasskeySignerKey(Address.forContractId(policyContractId));
    final scVal = PolicySignature();
    final signature = XdrSCMapEntry(scKey.toXdrSCVal(), scVal.toXdrSCVal());

    _addSignatureToEntry(entry, signature);

    return entry;
  }

  _addSignatureToEntry(
      SorobanAuthorizationEntry entry, XdrSCMapEntry signature) {
    if (entry.credentials.addressCredentials == null) {
      throw Exception("entry has no address credentials");
    }

    if (entry.credentials.addressCredentials!.signature.discriminant ==
        XdrSCValType.SCV_VOID) {
      entry.credentials.addressCredentials!.signature = XdrSCVal.forVec([
        XdrSCVal.forMap([signature])
      ]);
    } else if (entry.credentials.addressCredentials!.signature.discriminant ==
        XdrSCValType.SCV_VEC) {
      List<XdrSCMapEntry> newEntries =
          List<XdrSCMapEntry>.empty(growable: true);
      var currentMap =
          entry.credentials.addressCredentials!.signature.vec!.firstOrNull;
      if (currentMap != null && currentMap.map != null) {
        newEntries.addAll(currentMap.map!);
      }
      newEntries.add(signature);
      //Order the map by key
      newEntries.sort(_sigSortComparison);

      entry.credentials.addressCredentials!.signature.vec![0] =
          XdrSCVal.forMap(newEntries);
    } else {
      throw Exception("entry has invalid address credentials signature");
    }
  }

  /// Signs all SorobanAuthorization entries of the [transaction] with passkey credentials. Make sure that all
  /// entries have addressCredentials with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]
  /// to be set before signing. Provide [getPasskeyCredentials] so that the user can be asked for their credentials.
  Future<void> signTxAuthEntriesWithPasskey(Transaction transaction,
      {required Future<PublicKeyCredential> Function(
              {required CredentialLoginOptions options})
          getPasskeyCredentials,
      int? signaturesExpirationLedger}) async {
    for (Operation op in transaction.operations) {
      if (op is InvokeHostFunctionOperation) {
        for (SorobanAuthorizationEntry authEntry in op.auth) {
          if (signaturesExpirationLedger != null &&
              authEntry.credentials.addressCredentials != null) {
            authEntry.credentials.addressCredentials!
                .signatureExpirationLedger = signaturesExpirationLedger;
          }
          await signAuthEntryWithPasskey(authEntry, getPasskeyCredentials);
        }
      }
    }
  }

  /// Signs all SorobanAuthorization entries of the [transaction] with the given [signerKeypair] as as an ed25519 signer. Make sure that all
  /// entries have addressCredentials with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]
  /// to be set before signing. Provide [signerKeypair] including the private key for signing.
  Future<void> signTxAuthEntriesWithKeyPair(Transaction transaction,
      {required KeyPair signerKeypair, int? signaturesExpirationLedger}) async {
    for (Operation op in transaction.operations) {
      if (op is InvokeHostFunctionOperation) {
        for (SorobanAuthorizationEntry authEntry in op.auth) {
          if (signaturesExpirationLedger != null &&
              authEntry.credentials.addressCredentials != null) {
            authEntry.credentials.addressCredentials!
                .signatureExpirationLedger = signaturesExpirationLedger;
          }
          await signAuthEntryWithKeyPair(authEntry, signerKeypair);
        }
      }
    }
  }

  /// Signs all SorobanAuthorization entries of the [transaction] with the given [policyContractId] as as a policy signer. Make sure that all
  /// entries have addressCredentials with the expiration ledger sequence correctly set or provide a [signaturesExpirationLedger]
  /// to be set before signing.
  Future<void> signTxAuthEntriesWithPolicy(Transaction transaction,
      {required String policyContractId,
      int? signaturesExpirationLedger}) async {
    for (Operation op in transaction.operations) {
      if (op is InvokeHostFunctionOperation) {
        for (SorobanAuthorizationEntry authEntry in op.auth) {
          if (signaturesExpirationLedger != null &&
              authEntry.credentials.addressCredentials != null) {
            authEntry.credentials.addressCredentials!
                .signatureExpirationLedger = signaturesExpirationLedger;
          }
          await signAuthEntryWithPolicy(authEntry, policyContractId);
        }
      }
    }
  }

  /// Creates a transaction that adds a new secp256r1 signer to the wallet,
  /// identified by [keyId] and [publicKey] that can be obtained by calling [createKey].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> addSecp256r1(
    String txSourceAccountId,
    String keyId,
    String publicKey, {
    Map<Address, List<PasskeySignerKey>?>? limits,
    PasskeySignerStorage? storage,
    int? expiration,
  }) async {
    if (this.keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: this.keyId!);
    var keyIdBytes = base64Url.decode(base64Url.normalize(keyId));
    final publicKeyBytes = base64Url.decode(base64Url.normalize(publicKey));
    var signer = Secp256r1PasskeySigner(keyIdBytes, publicKeyBytes,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'add_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that updates the secp256r1 signer of the wallet,
  /// identified by [keyId] and [publicKey].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> updateSecp256r1(
      String txSourceAccountId, String keyId, String publicKey,
      {Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage,
      int? expiration}) async {
    if (this.keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: this.keyId!);
    var keyIdBytes = base64Url.decode(base64Url.normalize(keyId));
    final publicKeyBytes = base64Url.decode(base64Url.normalize(publicKey));
    var signer = Secp256r1PasskeySigner(keyIdBytes, publicKeyBytes,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'update_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that removes the secp256r1 signer of the wallet,
  /// identified by [keyId] and [publicKey].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> removeSecp256r1(
      String txSourceAccountId, String keyId, String publicKey) async {
    if (this.keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: this.keyId!);
    var keyIdBytes = base64Url.decode(base64Url.normalize(keyId));
    final publicKeyBytes = base64Url.decode(base64Url.normalize(publicKey));
    var signer = Secp256r1PasskeySigner(keyIdBytes, publicKeyBytes);

    final function = InvokeContractHostFunction(contractId, 'remove_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that adds a new ed25519 signer to the wallet,
  /// identified by [newSignerAccountId].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> addEd25519(
    String txSourceAccountId,
    String newSignerAccountId, {
    Map<Address, List<PasskeySignerKey>?>? limits,
    PasskeySignerStorage? storage,
    int? expiration,
  }) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    final publicKeyBytes = StrKey.decodeStellarAccountId(newSignerAccountId);
    var signer = Ed25519PasskeySigner(publicKeyBytes,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'add_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that updates the ed25519 signer of the wallet,
  /// identified by [signerAccountId].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> updateEd25519(
      String txSourceAccountId, String signerAccountId,
      {Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage,
      int? expiration}) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. Call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    final publicKeyBytes = StrKey.decodeStellarAccountId(signerAccountId);
    var signer = Ed25519PasskeySigner(publicKeyBytes,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'update_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that removes the ed25519 signer of the wallet,
  /// identified by [signerAccountId].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> removeEd25519(
      String txSourceAccountId, String signerAccountId) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. Call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    final publicKeyBytes = StrKey.decodeStellarAccountId(signerAccountId);
    var signer = Ed25519PasskeySigner(publicKeyBytes);

    final function = InvokeContractHostFunction(contractId, 'remove_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that adds a policy the wallet,
  /// identified by the [policyContractAddress].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> addPolicy(
      String txSourceAccountId, Address policyContractAddress,
      {Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage,
      int? expiration}) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    var signer = PolicyPasskeySigner(policyContractAddress,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'add_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that updates the policy of the wallet,
  /// identified by the [policyContractAddress].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> updatePolicy(
      String txSourceAccountId, Address policyContractAddress,
      {Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage,
      int? expiration}) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    var signer = PolicyPasskeySigner(policyContractAddress,
        expiration: expiration,
        limits: limits,
        storage: storage ?? PasskeySignerStorage.persistent);

    final function = InvokeContractHostFunction(contractId, 'update_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  /// Creates a transaction that removes the policy of the wallet,
  /// identified by the [policyContractAddress].
  /// Before calling this function, you must first connect your passkey kit instance
  /// to the wallet by using the [connectWallet] function.
  /// Returns a transaction, that can be sent by you to your soroban rpc server
  /// after signing with the source account keypair.
  Future<Transaction> removePolicy(
      String txSourceAccountId, Address policy) async {
    if (keyId == null) {
      throw Exception("wallet must be connected. call connectWallet first");
    }
    final contractId = _deriveContractId(keyId: keyId!);
    var signer = PolicyPasskeySigner(policy);

    final function = InvokeContractHostFunction(contractId, 'remove_signer',
        arguments: [signer.toXdrSCVal()]);

    return await _txForHostFunction(txSourceAccountId, function);
  }

  Future<Transaction> _txForHostFunction(
      String txSourceAccountId, HostFunction function) async {
    final operation = InvokeHostFuncOpBuilder(function).build();
    final sourceAccount = await server.getAccount(txSourceAccountId);
    if (sourceAccount == null) {
      var msg =
          "source account not found on the Stellar Network: $sourceAccount";
      dev.log(msg);
      throw Exception(msg);
    }

    final transaction =
        TransactionBuilder(sourceAccount).addOperation(operation).build();
    final request = SimulateTransactionRequest(transaction);
    final simulateResponse = await server.simulateTransaction(request);

    if (simulateResponse.resultError != null) {
      throw Exception("Could not simulate transaction");
    }

    transaction.sorobanTransactionData = simulateResponse.transactionData;
    transaction.addResourceFee(simulateResponse.minResourceFee!);
    transaction.setSorobanAuth(simulateResponse.sorobanAuth);

    return transaction;
  }

  int _sigSortComparison(XdrSCMapEntry a, XdrSCMapEntry b) {
    final propertyA =
        a.key.vec![0].sym! + a.key.vec![1].toBase64EncodedXdrString();
    final propertyB =
        b.key.vec![0].sym! + b.key.vec![1].toBase64EncodedXdrString();
    return propertyA.compareTo(propertyB);
  }

  Uint8List _getAuthPayload(SorobanAuthorizationEntry entry) {
    var addressCredentials = entry.credentials.addressCredentials;
    if (addressCredentials == null) {
      throw Exception("entry has no address credentials");
    }

    final preimage =
        XdrHashIDPreimage(XdrEnvelopeType.ENVELOPE_TYPE_SOROBAN_AUTHORIZATION);
    XdrHashIDPreimageSorobanAuthorization preimageSa =
        XdrHashIDPreimageSorobanAuthorization(
            XdrHash(network.networkId!),
            XdrInt64(addressCredentials.nonce),
            XdrUint32(addressCredentials.signatureExpirationLedger),
            entry.rootInvocation.toXdr());

    preimage.sorobanAuthorization = preimageSa;

    XdrDataOutputStream xdrOutputStream = XdrDataOutputStream();
    XdrHashIDPreimage.encode(xdrOutputStream, preimage);
    return Util.hash(Uint8List.fromList(xdrOutputStream.bytes));
  }

  Future<Transaction> _createAndSignDeployTx(
      {required String keyId,
      required Uint8List publicKey}) async {
    final server = SorobanServer(rpcUrl);
    server.enableLogging = true;

    final sourceAccId = walletKeyPair.accountId;
    final sourceAccount = await server.getAccount(sourceAccId);
    if (sourceAccount == null) {
      var msg =
          "source account not found on the Stellar Network: $sourceAccount";
      dev.log(msg);
      throw Exception(msg);
    }

    var credentialsIdBytes = base64Url.decode(base64Url.normalize(keyId));
    var signer = Secp256r1PasskeySigner(credentialsIdBytes, publicKey,
        storage: PasskeySignerStorage.persistent);

    var function = CreateContractWithConstructorHostFunction(
        Address.forAccountId(sourceAccId),
        walletWasmHash,
        [signer.toXdrSCVal()],
        salt: XdrUint256(_getContractSalt(keyId)));

    final operation = InvokeHostFuncOpBuilder(function).build();

    final transaction =
        TransactionBuilder(sourceAccount).addOperation(operation).build();
    final request = SimulateTransactionRequest(transaction);
    final simulateResponse = await server.simulateTransaction(request);

    if (simulateResponse.resultError != null) {
      throw Exception("Could not simulate transaction");
    }

    transaction.sorobanTransactionData = simulateResponse.transactionData;
    transaction.addResourceFee(simulateResponse.minResourceFee!);
    transaction.setSorobanAuth(simulateResponse.sorobanAuth);

    transaction.sign(walletKeyPair, network);
    return transaction;
  }

  /// Extracts the public key from the authenticator attestation [response] received
  /// from the webauthn registration.
  static Uint8List? getPublicKey(AuthAttestationResponse response) {
    final publicKeyStr = response.publicKey;

    Uint8List? publicKey = publicKeyStr != null
        ? base64Url.decode(base64Url.normalize(publicKeyStr))
        : null;

    if (publicKey == null ||
        publicKey.isEmpty ||
        publicKey.first != 0x04 ||
        publicKey.length != 65) {
      // see https://www.w3.org/TR/webauthn/#attestation-object
      final authenticatorDataStr = response.authenticatorData;
      if (authenticatorDataStr != null) {
        Uint8List authData =
            base64Url.decode(base64Url.normalize(authenticatorDataStr));
        // Get credentialIdLength, which is at offset 53 (and is big-endian)
        final credentialIdLength = (authData[53] << 8) + authData[54];
        final x =
            authData.sublist(65 + credentialIdLength, 97 + credentialIdLength);
        final y = authData.sublist(
            100 + credentialIdLength, 132 + credentialIdLength);
        return Uint8List.fromList([
          [0x04],
          x,
          y
        ].expand((x) => x).toList());
      }

      final attestationObjectStr = response.attestationObject;
      if (attestationObjectStr != null) {
        Uint8List attestationObject =
            base64Url.decode(base64Url.normalize(attestationObjectStr));
        final publicKeyPrefixSlice = Uint8List.fromList(
            [0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        var startIndex =
            attestationObject.indexOfElements(publicKeyPrefixSlice);
        if (startIndex != -1) {
          startIndex = startIndex + publicKeyPrefixSlice.length;
          final x = attestationObject.sublist(startIndex, 32 + startIndex);
          final y = attestationObject.sublist(35 + startIndex, 67 + startIndex);
          return Uint8List.fromList([
            [0x04],
            x,
            y
          ].expand((x) => x).toList());
        }
      }
    }
    return publicKey;
  }

  /// Generates the wallet contract salt from the webauthn registration response credentials id or
  /// authentication response credentials id.
  static Uint8List _getContractSalt(String credentialsId) {
    return Util.hash(base64Url.decode(base64Url.normalize(credentialsId)));
  }

  /// Derives the wallet contract id from the webauthn registration response credentials id or
  /// authentication response credentials id: [keyId].
  String _deriveContractId({required String keyId}) {
    var contractSalt = _getContractSalt(keyId);

    final preimage =
        XdrHashIDPreimage(XdrEnvelopeType.ENVELOPE_TYPE_CONTRACT_ID);
    final contractIdPreimage = XdrContractIDPreimage(
        XdrContractIDPreimageType.CONTRACT_ID_PREIMAGE_FROM_ADDRESS);
    contractIdPreimage.address =
        XdrSCAddress.forAccountId(walletKeyPair.accountId);
    contractIdPreimage.salt = XdrUint256(contractSalt);
    final preimageCID = XdrHashIDPreimageContractID(
        XdrHash(network.networkId!), contractIdPreimage);
    preimage.contractID = preimageCID;
    XdrDataOutputStream xdrOutputStream = XdrDataOutputStream();
    XdrHashIDPreimage.encode(xdrOutputStream, preimage);
    return StrKey.encodeContractId(
        Util.hash(Uint8List.fromList(xdrOutputStream.bytes)));
  }

  /// Convert EcdsaSignatureAsn [signature] received from the webauthn authentication
  /// to compact. The resulting compact signature is to be used as authentication
  /// signature for the webauthn (account) contract __checkAuth invocation.
  static Uint8List _compactSignature(Uint8List signature) {
    // Decode the DER signature
    var offset = 2;
    final rLength = signature[offset + 1];
    final r = signature.sublist(offset + 2, offset + 2 + rLength);

    offset += 2 + rLength;

    final sLength = signature[offset + 1];
    final s = signature.sublist(offset + 2, offset + 2 + sLength);

    // Convert r and s to BigInt
    final rHexStr = Util.bytesToHex(r);
    final sHexStr = Util.bytesToHex(s);
    final rBigInt = BigInt.parse('0x$rHexStr');
    var sBigInt = BigInt.parse('0x$sHexStr');

    // Ensure s is in the low-S form
    // https://github.com/stellar/stellar-protocol/discussions/1435#discussioncomment-8809175
    // https://discord.com/channels/897514728459468821/1233048618571927693
    // Define the order of the curve secp256r1
    // https://github.com/RustCrypto/elliptic-curves/blob/master/p256/src/lib.rs#L72
    final BigInt n = BigInt.parse(
        '0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    final BigInt halfN = n ~/ BigInt.from(2);

    if (sBigInt > halfN) {
      sBigInt = n - sBigInt;
    }

    // Convert back to buffers and ensure they are 32 bytes
    final rPadded = rBigInt.toRadixString(16).padLeft(64, '0');
    final sLowS = sBigInt.toRadixString(16).padLeft(64, '0');
    final rPaddedBytes = Util.hexToBytes(rPadded);
    final sLowSBytes = Util.hexToBytes(sLowS);

    // Concatenate r and low-s
    var b = BytesBuilder();
    b.add(rPaddedBytes);
    b.add(sLowSBytes);

    final concatSignature = b.toBytes();
    return concatSignature;
  }
}

/// Contains the elements needed to create a new wallet.
class CreateWalletResponse {
  /// keyId identifying the user/signer by their passkey credentials
  String keyId;

  /// Derived contract id of the new wallet that can be created.
  String contractId;

  /// The transaction that creates the smart wallet if sent to stellar/soroban.
  Transaction transaction;

  CreateWalletResponse(this.keyId, this.contractId, this.transaction);
}

/// Contains new created credentials
class CreateKeyResponse {
  /// keyId identifying the user/signer by their passkey credentials
  String keyId;

  /// publicKey of the user/signer identified by keyId.
  String publicKey;

  CreateKeyResponse(this.keyId, this.publicKey);
}

/// Contains the elements obtained by connecting a wallet to the passkey kit instance.
class ConnectWalletResponse {
  /// keyId identifying the user/signer by their passkey credentials
  String keyId;

  /// Contract id of the connected wallet.
  String contractId;

  /// username if it could be extracted
  String? username;

  ConnectWalletResponse(this.keyId, this.contractId, {this.username});
}

/// Abstract class representing a passkey signer.
abstract class PasskeySigner {
  PasskeySignerType type;
  int? expiration;
  Map<Address, List<PasskeySignerKey>?>? limits;
  PasskeySignerStorage? storage;

  PasskeySigner(this.type, {this.expiration, this.limits, this.storage});

  List<XdrSCVal> _signerArgs() {
    List<XdrSCVal> args = List<XdrSCVal>.empty(growable: true);
    expiration != null
        ? args.add(XdrSCVal.forVec([XdrSCVal.forU32(expiration!)]))
        : args.add(XdrSCVal.forVec([XdrSCVal.forVoid()]));
    if (limits != null) {
      var mapEntries = List<XdrSCMapEntry>.empty(growable: true);
      limits!.forEach((key, value) {
        if (value != null) {
          List<XdrSCVal> elements = List<XdrSCVal>.empty(growable: true);
          for (var i = 0; i < value.length; i++) {
            elements.add(value[i].toXdrSCVal());
          }
          mapEntries
              .add(XdrSCMapEntry(key.toXdrSCVal(), XdrSCVal.forVec(elements)));
        } else {
          mapEntries.add(XdrSCMapEntry(key.toXdrSCVal(), XdrSCVal.forVoid()));
        }
      });

      args.add(XdrSCVal.forVec([XdrSCVal.forMap(mapEntries)]));
    } else {
      args.add(XdrSCVal.forVec([XdrSCVal.forVoid()]));
    }
    storage != null
        ? args.add(XdrSCVal.forVec([XdrSCVal.forSymbol(storage!.value)]))
        : args.add(XdrSCVal.forVoid());

    return args;
  }

  XdrSCVal toXdrSCVal();
}

/// Represents a policy passkey signer.
class PolicyPasskeySigner extends PasskeySigner {
  /// Address of the policy contract.
  Address address;

  PolicyPasskeySigner(this.address,
      {int? expiration,
      Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage})
      : super(PasskeySignerType.policy,
            expiration: expiration, limits: limits, storage: storage);

  @override
  XdrSCVal toXdrSCVal() {
    List<XdrSCVal> elements = List<XdrSCVal>.empty(growable: true);
    elements.add(XdrSCVal.forSymbol(type.value));
    elements.add(address.toXdrSCVal());
    elements.addAll(_signerArgs());
    return XdrSCVal.forVec(elements);
  }
}

/// Represents a ed25519 passkey signer.
class Ed25519PasskeySigner extends PasskeySigner {
  /// bytes of the signers public key. You can get them from the keypair or
  /// by using StrKey
  Uint8List publicKeyBytes;

  Ed25519PasskeySigner(this.publicKeyBytes,
      {int? expiration,
      Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage})
      : super(PasskeySignerType.ed25519,
            expiration: expiration, limits: limits, storage: storage);

  @override
  XdrSCVal toXdrSCVal() {
    List<XdrSCVal> elements = List<XdrSCVal>.empty(growable: true);
    elements.add(XdrSCVal.forSymbol(type.value));
    elements.add(XdrSCVal.forBytes(publicKeyBytes));
    elements.addAll(_signerArgs());
    return XdrSCVal.forVec(elements);
  }
}

/// Represents a secp256r1 passkey signer.
class Secp256r1PasskeySigner extends PasskeySigner {
  /// keyId obtained by creating a new key. See [createKey].
  Uint8List keyId;

  /// public key bytes obtained by creating a new key. See [createKey].
  Uint8List publicKey;

  Secp256r1PasskeySigner(this.keyId, this.publicKey,
      {int? expiration,
      Map<Address, List<PasskeySignerKey>?>? limits,
      PasskeySignerStorage? storage})
      : super(PasskeySignerType.secp256r1,
            expiration: expiration, limits: limits, storage: storage);

  @override
  XdrSCVal toXdrSCVal() {
    List<XdrSCVal> elements = List<XdrSCVal>.empty(growable: true);
    elements.add(XdrSCVal.forSymbol(type.value));
    elements.add(XdrSCVal.forBytes(keyId));
    elements.add(XdrSCVal.forBytes(publicKey));
    elements.addAll(_signerArgs());
    return XdrSCVal.forVec(elements);
  }
}

abstract class PasskeySignerKey {
  PasskeySignerType type;
  PasskeySignerKey(this.type);

  XdrSCVal toXdrSCVal();
}

class PolicyPasskeySignerKey extends PasskeySignerKey {
  Address policyAddress;
  PolicyPasskeySignerKey(this.policyAddress) : super(PasskeySignerType.policy);

  @override
  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec(
        [XdrSCVal.forSymbol(type.value), policyAddress.toXdrSCVal()]);
  }
}

class Ed25519PasskeySignerKey extends PasskeySignerKey {
  Uint8List publicKey;
  Ed25519PasskeySignerKey(this.publicKey) : super(PasskeySignerType.ed25519);

  @override
  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec(
        [XdrSCVal.forSymbol(type.value), XdrSCVal.forBytes(publicKey)]);
  }
}

class Secp256r1PasskeySignerKey extends PasskeySignerKey {
  Uint8List keyId;
  Secp256r1PasskeySignerKey(this.keyId) : super(PasskeySignerType.secp256r1);

  @override
  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec(
        [XdrSCVal.forSymbol(type.value), XdrSCVal.forBytes(keyId)]);
  }
}

class Secp256r1Signature {
  Uint8List authenticatorData;
  Uint8List clientDataJson;
  Uint8List signature;

  Secp256r1Signature(
      this.authenticatorData, this.clientDataJson, this.signature);

  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec([
      XdrSCVal.forSymbol("Secp256r1"),
      XdrSCVal.forMap([
        XdrSCMapEntry(XdrSCVal.forSymbol('authenticator_data'),
            XdrSCVal.forBytes(authenticatorData)),
        XdrSCMapEntry(XdrSCVal.forSymbol('client_data_json'),
            XdrSCVal.forBytes(clientDataJson)),
        XdrSCMapEntry(
            XdrSCVal.forSymbol('signature'), XdrSCVal.forBytes(signature)),
      ])
    ]);
  }
}

class Ed25519Signature {
  Uint8List signature;

  Ed25519Signature(this.signature);

  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec(
        [XdrSCVal.forSymbol("Ed25519"), XdrSCVal.forBytes(signature)]);
  }
}

class PolicySignature {
  PolicySignature();

  XdrSCVal toXdrSCVal() {
    return XdrSCVal.forVec([XdrSCVal.forSymbol("Policy")]);
  }
}

enum PasskeySignerType {
  policy("Policy"),
  ed25519("Ed25519"),
  secp256r1("Secp256r1");

  final String value;
  const PasskeySignerType(this.value);
}

enum PasskeySignerStorage {
  persistent("Persistent"),
  temporary("Temporary");

  final String value;
  const PasskeySignerStorage(this.value);
}
