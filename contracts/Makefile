export STELLAR_NETWORK=testnet
export STELLAR_ACCOUNT=alice
# export STELLAR_NETWORK=vc
# export STELLAR_ACCOUNT=live

# TESTNET
export SMART_WALLET_WASM=fb077ee782a6066a07d8e26146477561525143507be787415659dac546d11a7f

build:
	rm -rf out/
	rm -rf smart-wallet/target/wasm32-unknown-unknown/

	stellar contract build
		
	@cd smart-wallet && stellar contract build --package smart-wallet --out-dir ../out
	stellar contract optimize --wasm ./out/smart_wallet.wasm

install:
	stellar contract install --wasm ./out/smart_wallet.optimized.wasm --source $(STELLAR_ACCOUNT)

bindings:
	stellar contract bindings typescript --id CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC --network $(STELLAR_NETWORK) --output-dir ./out/sac-sdk --overwrite
	stellar contract bindings typescript --wasm ./target/wasm32-unknown-unknown/release/smart_wallet.wasm --network $(STELLAR_NETWORK) --output-dir ./out/passkey-kit-sdk --overwrite

fmt:
	@cd smart-wallet && cargo fmt --all

clean:
	rm -rf out/
	rm -rf smart-wallet/target/
	@cd smart-wallet && cargo clean