# Flutter Passkey Kit Demo App

A demo app using the [flutter passkey kit](https://github.com/Soneso/flutter_passkey_kit) functionality to create and manage smart wallets on soroban.

## Getting Started

To use the demo app, you must first build the smart wallet contract from the `/contracts` folder of the passkey kit project:

```shell
cd contracts
make build
```

Next, install the contract using the stellar-cli. E.g.:

```shell
cd out
stellar contract install --source-account alice --wasm smart_wallet.optimized.wasm --rpc-url https://soroban-testnet.stellar.org --network-passphrase 'Test SDF Network ; September 2015'
```

You will obtain the `wasm_hash` of the installed contract that will look similar to this:

```shell
6e7d01475c89eee531a91ec0f8f5348beda9d9e232a4d383da02fc9afc3c221b
```

### .env
Go back to the `/example` folder and update the `.env` file by filling the value of `wallet_wasm_hash` with the obtained `wasm_hash`.
Also update the other values of `.env` as described in the following chapters.

#### rp_id

`rp_id` is the name of the domain hosting your DAL file. You can read more about how to create and deploy your DAL file [here](https://passkeys-auth.com/docs/implementation/flutter/android/).

Hint: To get the android app fingerprint you can use this command:

```shell
keytool -list -v -keystore ~/.android/debug.keystore -alias androiddebugkey -storepass android -keypass android
```

#### rpc_url

`rpc_url` is the url of the soroban rpc server to be used for requests and to send transactions to soroban.

E.g. `https://soroban-testnet.stellar.org`

#### horizon_url

`horizon_url` is the url of the horizon instance to be used for requests and to send transactions to the stellar network. E.g. `https://horizon-testnet.stellar.org` 

#### network_passphrase

`network_passphrase` of the network to be used. E.g. for testnet: `Test SDF Network ; September 2015`

#### submitter_secret

`submitter_secret` is the secret key of the stellar account that is used to sign and send transactions. Make sure that the account is funded.

#### native_sac_cid

`native_sac_cid` is the contract id of the XLM SAC to make transfers (payments). For example `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC`on testnet.

#### ed25519Signer_secret

`ed25519Signer_secret` is the secret seed of a stellar account keypair to be used as a signer for the ed25519Signer demo.

#### sample_policy_cid

`sample_policy_cid` is the contract id of a deployed policy contract to be used in the policy demo. An example policy contract can be found in in the `/contracts` folder of the passkey kit project.


### Smart Contracts

Make yourself familiar with the smart wallet contracts from the `/contracts` folder of the passkey kit project. They were implemented by kalepail as a part of the [TypeScript PasskeyKit](https://github.com/kalepail/passkey-kit), also provided by kalepail.

### Start the app

After deploying your DAL file and filling the .env values, start the app and create a new wallet. After connecting to the new created wallet, you will find the demo functionality to interact with the wallet.
Use the source code, to understand how the demo app uses the passkey kit.


