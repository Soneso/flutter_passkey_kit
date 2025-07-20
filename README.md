
## Flutter Passkey Kit for Soroban Smart Wallets

> [!WARNING]  
> Code in this repo is demo material only. It has not been audited. Do not use to hold, protect, or secure anything.

This is an experimental library for creating and managing Soroban smart wallets using passkeys.

## Getting started

You can learn what soroban smart wallets are on this [Stellar page](https://developers.stellar.org/docs/build/apps/smart-wallets).
The official Stellar developer docs regarding smart wallets can be found [here](https://developers.stellar.org/docs/build/apps/smart-wallets).

This Flutter Passkey Kit is inspired by the [TypeScript PasskeyKit](https://github.com/kalepail/passkey-kit) provided by kalepail.

## Demo app

You can find a demo app using this library in the `/example` folder. 

Probably the best way to familiarize yourself with the functionality of the passkey kit is to use the demo app by cloning this repo.

The docs of the demo app can be found [here](https://github.com/Soneso/flutter_passkey_kit/blob/main/example/README.md)

## Functionality

- create wallet
- connect wallet
- create keyIds and public keys for new secp256r1 signers
- add/update/remove secp256r1 and ed25519 signers
- add/update/remove policies
- sign auth entries with secp256r1, ed25519 and policy signers

## Installation

- add `flutter_passkey_kit: ^0.0.2`  to your package's pubspec.yaml