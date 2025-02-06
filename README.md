
## Flutter Passkey Kit for Soroban Smart Wallets

> [!WARNING]  
> Code in this repo is demo material only. It has not been audited. Do not use to hold, protect, or secure anything.

This is an experimental library for creating and managing Soroban smart wallets using passkeys.

## Getting started

You can learn what soroban smart wallets are on this [Stellar page](https://developers.stellar.org/docs/build/apps/smart-wallets).
The official Stellar developer docs regarding smart wallets can be found [here](https://developers.stellar.org/docs/build/apps/smart-wallets).

This Flutter Passkey Kit is inspired by the [TypeScript PasskeyKit](https://github.com/kalepail/passkey-kit) provided by kalepail.

## Example app

You can find an example app using this library in the `/example` folder.

To use the example app, you must first build the smart wallet contract from the `/contracts` folder of the passkey kit project:

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

Go back to the `/example` folder and update the `.env` file by filling the value of `wallet_wasm_hash` with the obtained `wasm_hash`.
Also update the other values of `.env`.
