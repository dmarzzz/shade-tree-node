//! Byte-for-byte parity between `shadenet::eth` and `ethers-core`, which it replaces. Runs while
//! both are in the tree; removed together with the ethers-core dependency.

use ethers_core::abi::{encode as e_encode, Token as EToken};
use ethers_core::k256::ecdsa::{RecoveryId, Signature as RSig, SigningKey};
use ethers_core::types::{
    transaction::eip2718::TypedTransaction, Address as EAddress, Bytes, Eip1559TransactionRequest,
    NameOrAddress, Signature, U256 as EU256, U64,
};
use ethers_core::utils::{id, secret_key_to_address};
use shadenet::eth::{self, Address, Eip1559, Token, Wallet, U256};

/// A small deterministic PRNG so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn uint(&mut self) -> Vec<u8> {
        let len = (self.next() % 33) as usize;
        self.bytes(len)
    }
}

fn eu(bytes: &[u8]) -> EU256 {
    EU256::from_big_endian(bytes)
}
fn su(bytes: &[u8]) -> U256 {
    U256::from_big_endian(bytes).unwrap()
}

#[test]
fn abi_calldata_matches_ethers() {
    let mut rng = Rng(0x5eed);
    for _ in 0..200 {
        let a = rng.uint();
        let addr = rng.bytes(20);
        let blob_len = (rng.next() % 300) as usize;
        let blob = rng.bytes(blob_len);
        let ours = eth::calldata(
            "withdraw(uint256,address,bytes)",
            &[
                Token::Uint(su(&a)),
                Token::Address(Address(addr.clone().try_into().unwrap())),
                Token::Bytes(blob.clone()),
            ],
        );
        let mut theirs = id("withdraw(uint256,address,bytes)")[..4].to_vec();
        theirs.extend(e_encode(&[
            EToken::Uint(eu(&a)),
            EToken::Address(EAddress::from_slice(&addr)),
            EToken::Bytes(blob),
        ]));
        assert_eq!(ours, theirs);
    }
}

#[test]
fn signed_eip1559_transactions_match_ethers() {
    let mut rng = Rng(0xfeed);
    for _ in 0..100 {
        let mut key = rng.bytes(32);
        key[0] &= 0x7f; // stay below the curve order
        key[31] |= 1;
        let key_hex = hex::encode(&key);
        let wallet = Wallet::from_hex(&key_hex).unwrap();
        let signer = SigningKey::from_slice(&key).unwrap();
        assert_eq!(wallet.address.0, secret_key_to_address(&signer).0);

        let (nonce, tip, fee, gas, value) =
            (rng.uint(), rng.uint(), rng.uint(), rng.uint(), rng.uint());
        let to = rng.bytes(20);
        let data_len = (rng.next() % 200) as usize;
        let data = rng.bytes(data_len);
        let chain_id = rng.next() % 20_000_000;

        let ours = wallet
            .sign(&Eip1559 {
                chain_id,
                nonce: su(&nonce),
                max_priority_fee_per_gas: su(&tip),
                max_fee_per_gas: su(&fee),
                gas: su(&gas),
                to: Address(to.clone().try_into().unwrap()),
                value: su(&value),
                data: data.clone(),
            })
            .unwrap();

        let tx = TypedTransaction::Eip1559(Eip1559TransactionRequest {
            from: None,
            to: Some(NameOrAddress::Address(EAddress::from_slice(&to))),
            gas: Some(eu(&gas)),
            value: Some(eu(&value)),
            data: Some(Bytes::from(data)),
            nonce: Some(eu(&nonce)),
            access_list: Default::default(),
            max_priority_fee_per_gas: Some(eu(&tip)),
            max_fee_per_gas: Some(eu(&fee)),
            chain_id: Some(U64::from(chain_id)),
        });
        let (sig, rec): (RSig, RecoveryId) = signer
            .sign_prehash_recoverable(tx.sighash().as_bytes())
            .unwrap();
        let bytes = sig.to_bytes();
        let theirs = tx.rlp_signed(&Signature {
            r: EU256::from_big_endian(&bytes[..32]),
            s: EU256::from_big_endian(&bytes[32..]),
            v: u64::from(u8::from(rec)),
        });
        assert_eq!(ours, theirs.to_vec(), "chain {chain_id}");
    }
}
