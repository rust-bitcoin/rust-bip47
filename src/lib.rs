// Rust BIP47 Implementation
// Written in 2021 by
//  Straylight <https://github.com/straylight-orbit>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

//! # Rust BIP47 Library
//!
//! This library implements the BIP47 standard and provides functionality
//! for generating static payment codes that two parties can use to create
//! a private payment address space between them.
//!
//! Original specification: [BIP-0047](https://github.com/bitcoin/bips/blob/master/bip-0047.mediawiki).
//!
//! ## Usage
//! ```
//! # extern crate bitcoin;
//! # extern crate bip47;
//! # use {bip47::PrivateCode, bip47::PublicCode, bitcoin::Network};
//! # let alice_seed = [0_u8];
//! // Alice constructs her own payment code using a BIP32 seed
//! let alice_private = PrivateCode::from_seed(&alice_seed, 0, Network::Bitcoin).unwrap();
//!
//! // Alice parses Bob's payment code
//! let bob_public = PublicCode::from_wif("PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97").unwrap();
//!
//! // Alice calculates Bob's receive address at index 0, known only to them
//! let bob_address_0 = bob_public.address(&alice_private, 0, false).unwrap();
//!
//! // Alice can now pay Bob privately
//! assert_eq!("12edoJAofkjCsWrtmVjuQgMUKJ6Z7Ntpzx", bob_address_0.to_string());
//!
//! ```

use std::str::FromStr;

pub extern crate bitcoin;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::address::{self, Address};
use bitcoin::util::bip32::{ChainCode, ChildNumber, DerivationPath, ExtendedPubKey};
use bitcoin::util::psbt::serialize::Serialize;
use bitcoin::util::{base58, bip32};
use bitcoin::{secp256k1, OutPoint, PrivateKey, PublicKey, Script, Transaction};

const PAYMENT_CODE_BIN_LENGTH: usize = 80;
const LETTER_P: u8 = 0x47;

/// Represents the version number of a BIP47 payment code.
#[derive(Debug, Clone)]
pub enum Version {
    V1,
    V2,
}

impl Version {
    /// Returns the byte representation of a version.
    pub fn as_byte(&self) -> u8 {
        match self {
            Version::V1 => 0x01,
            Version::V2 => 0x02,
        }
    }

    /// Constructs a `Version` enum from a byte
    pub fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            0x01 => Ok(Version::V1),
            0x02 => Ok(Version::V2),
            _ => Err(Error::UnsupportedVersion),
        }
    }
}

/// Represents the private side of a payment code, as seen from the perspective of the sender.
/// This is what the sender will use in conjunction with a receiver's public payment code in order
/// to be able to send funds.
pub struct PrivateCode {
    identity_key: bip32::ExtendedPrivKey,
    curve: Secp256k1<secp256k1::All>,
    network: bitcoin::Network,
}

impl PrivateCode {
    /// Constructs a new payment code from the private side using a BIP32 seed.
    pub fn from_seed(
        seed: &[u8],
        account: u32,
        network: bitcoin::Network,
    ) -> Result<Self, bip32::Error> {
        let curve = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/47'/0'/{}'", account))?;
        let root_key = bip32::ExtendedPrivKey::new_master(network, seed)?;
        let identity_key = root_key.derive_priv(&curve, &path)?;

        Ok(Self {
            identity_key,
            curve,
            network,
        })
    }

    /// Constructs a new **ephemeral** payment code at the given index from the private side using a BIP32 seed.
    pub fn from_seed_ephemeral(
        seed: &[u8],
        account: u32,
        network: bitcoin::Network,
        ephemeral_index: u32,
    ) -> Result<Self, bip32::Error> {
        let curve = Secp256k1::new();
        let path =
            DerivationPath::from_str(&format!("m/47'/0'/{}'/{}'", account, ephemeral_index))?;
        let root_key = bip32::ExtendedPrivKey::new_master(network, seed)?;
        let identity_key = root_key.derive_priv(&curve, &path)?;

        Ok(Self {
            identity_key,
            curve,
            network,
        })
    }

    /// Generates a version 1 public payment code matching this private payment code, optionally with bitmessage.
    pub fn v1_public_code(&self, bitmessage: Option<BitMessagePreference>) -> PublicCode {
        let xpub = ExtendedPubKey::from_private(&self.curve, &self.identity_key);

        PublicCode {
            version: Version::V1,
            bitmessage,
            xpub,
            curve: self.curve.clone(),
            network: self.network,
        }
    }

    /// Generates a version 2 public payment code matching this private payment code.
    pub fn v2_public_code(&self) -> PublicCode {
        let xpub = ExtendedPubKey::from_private(&self.curve, &self.identity_key);

        PublicCode {
            version: Version::V1,
            bitmessage: None,
            xpub,
            curve: self.curve.clone(),
            network: self.network,
        }
    }

    /// Derives a child private key at the given index. If the result is invalid, the index should be incremented.
    fn child(&self, i: u32) -> Result<PrivateKey, bip32::Error> {
        let child_number = ChildNumber::from_normal_idx(i)?;
        let key = self.identity_key.ckd_priv(&self.curve, child_number)?;

        Ok(key.private_key)
    }

    /// Derives a receive private key at the given index, with respect to a public payment code. Used for spending purposes.
    /// If the index is invalid, it should be incremented.
    pub fn private_key(&self, sender_code: &PublicCode, i: u32) -> Result<PrivateKey, Error> {
        let sk = self.child(i)?;
        let pk = sender_code.child(0)?;
        let sp = secret_point(&sk, pk)?;
        let ss = shared_secret(sp)?;

        let mut sk_prime = sk.key;
        sk_prime.add_assign(&ss)?;
        let sk_prime = PrivateKey::new(sk_prime, self.network);

        Ok(sk_prime)
    }

    /// Derives a receive address at the given index. If the index is invalid, it should be incremented.
    pub fn address(
        &self,
        sender_code: &PublicCode,
        i: u32,
        segwit: bool,
    ) -> Result<Address, Error> {
        let sk_prime = self.private_key(sender_code, i)?;
        let pk_prime = PublicKey::from_private_key(&self.curve, &sk_prime);

        if segwit {
            Address::p2wpkh(&pk_prime, self.network).map_err(Error::Address)
        } else {
            Ok(Address::p2pkh(&pk_prime, self.network))
        }
    }
}

/// Represents the public side of a payment code. This is what the party that wishes to receive
/// funds shares with sending parties.
#[derive(Debug)]
pub struct PublicCode {
    version: Version,
    bitmessage: Option<BitMessagePreference>,
    xpub: ExtendedPubKey,
    curve: Secp256k1<secp256k1::All>,
    pub network: bitcoin::Network,
}

impl PublicCode {
    /// The version of this BIP47 payment code.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// Parses a WIF-formatted payment code.
    pub fn from_wif(payment_code: &str) -> Result<Self, Error> {
        PublicCode::try_from_str(payment_code)
    }

    /// Returns the notification mode to be used with this payment code.
    pub fn notification_mode(&self) -> NotificationMode {
        match &self.version {
            Version::V1 => match self.bitmessage.as_ref() {
                Some(bitmessage) => NotificationMode::Bitmessage(Bitmessage {
                    code: self,
                    preferences: bitmessage,
                }),
                None => NotificationMode::BasicTransaction(BasicTransaction(self)),
            },
            Version::V2 => NotificationMode::BloomMultisig(BloomMultisig(self)),
        }
    }

    /// Derives the child public key at the given index. If the result is invalid, the index should be incremented.
    fn child(&self, i: u32) -> Result<PublicKey, bip32::Error> {
        let child_number = ChildNumber::from_normal_idx(i)?;
        let key = self.xpub.ckd_pub(&self.curve, child_number)?;

        Ok(key.public_key)
    }

    /// Derives a send address at the given index. If the index is invalid, it should be incremented.
    pub fn address(&self, code: &PrivateCode, i: u32, segwit: bool) -> Result<Address, Error> {
        let sk = code.child(0)?;
        let pk = self.child(i)?;
        let sp = secret_point(&sk, pk)?;
        let ss = shared_secret(sp)?;

        let ss = secp256k1::SecretKey::from_slice(&ss)?;
        let sg = secp256k1::PublicKey::from_secret_key(&self.curve, &ss);
        let pk_prime = PublicKey::new(sg.combine(&pk.key)?);

        if segwit {
            Address::p2wpkh(&pk_prime, self.network).map_err(Error::Address)
        } else {
            Ok(Address::p2pkh(&pk_prime, self.network))
        }
    }

    /// Interprets the payment code as an 80 byte long array.
    fn as_bytes(&self) -> [u8; PAYMENT_CODE_BIN_LENGTH] {
        let mut payment_code = [0_u8; PAYMENT_CODE_BIN_LENGTH];

        payment_code[0] = self.version.as_byte();
        payment_code[1] = if self.bitmessage.is_some() {
            0x80
        } else {
            0x00
        };
        payment_code[2..35].copy_from_slice(&self.xpub.public_key.serialize());
        payment_code[35..67].copy_from_slice(self.xpub.chain_code.as_bytes());

        if let Some(bitmessage) = &self.bitmessage {
            payment_code[67] = bitmessage.version;
            payment_code[68] = bitmessage.stream_number;
        }

        payment_code
    }

    /// Attempts to extract a public payment code from a notification transaction. If the designated pubkey
    /// and input are unknown and set to `None`, automatic extraction will be attempted. They can also be
    /// supplied if they are known (for example if acquired through a side channel).
    pub fn from_notification(
        receiver_code: &PrivateCode,
        designated: Option<(PublicKey, OutPoint)>,
        tx: &Transaction,
    ) -> Result<Self, Error> {
        let (designated_pk, designated_utxo) =
            designated
                .or_else(|| find_designated(tx))
                .ok_or(Error::Notification(
                    "Designated pubkey and output not found",
                ))?;

        let notification_sk = receiver_code.child(0)?;

        let blinding_factor = blinding_factor(&notification_sk, &designated_pk, &designated_utxo)?;

        let op_return = tx
            .output
            .iter()
            .find(|out| out.script_pubkey.is_op_return())
            .ok_or(Error::Notification("OP_RETURN not found"))?;

        use bitcoin::blockdata::script::Instruction::PushBytes;

        // skip the OP_RETURN opcode, move on to the actual bytes
        if let Some(Ok(PushBytes(data))) = op_return.script_pubkey.instructions().nth(1) {
            if data.len() == PAYMENT_CODE_BIN_LENGTH {
                let mut code_bytes: [u8; PAYMENT_CODE_BIN_LENGTH] = [0; PAYMENT_CODE_BIN_LENGTH];
                code_bytes.copy_from_slice(data);

                blind_payment_code(&mut code_bytes, &blinding_factor);

                PublicCode::try_from_bytes(&code_bytes[..])
            } else {
                Err(Error::Notification("OP_RETURN incorrect length"))
            }
        } else {
            Err(Error::Notification("OP_RETURN not found"))
        }
    }
}

impl std::fmt::Display for PublicCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.as_bytes();
        let mut extended: Vec<u8> = Vec::with_capacity(1 + PAYMENT_CODE_BIN_LENGTH);

        extended.push(LETTER_P);
        extended.extend_from_slice(&bytes);

        base58::check_encode_slice_to_fmt(f, &extended)
    }
}

impl PublicCode {
    fn try_from_bytes(payment_code: &[u8]) -> Result<Self, Error> {
        if payment_code.len() != PAYMENT_CODE_BIN_LENGTH {
            return Err(Error::Format("Incorrect binary length"));
        }

        let version = Version::from_byte(payment_code[0])?;
        let bitmessage = payment_code[1] == 0x80;
        let public_key = PublicKey::from_slice(&payment_code[2..35])?;
        let chain_code = ChainCode::from(&payment_code[35..67]);
        let bitmessage = if bitmessage {
            Some(BitMessagePreference {
                version: payment_code[67],
                stream_number: payment_code[68],
            })
        } else {
            None
        };

        // when parsing a WIF-formatted paymenty code, we assume mainnet
        let network = bitcoin::Network::Bitcoin;

        let xpub = ExtendedPubKey {
            network,
            chain_code,
            child_number: ChildNumber::Normal { index: 0 },
            depth: 3,
            parent_fingerprint: bip32::Fingerprint::default(),
            public_key,
        };

        Ok(Self {
            version,
            bitmessage,
            xpub,
            curve: Secp256k1::new(),
            network,
        })
    }

    fn try_from_str(value: &str) -> Result<Self, Error> {
        let payment_code = base58::from_check(value).map_err(Error::Base58)?;

        if payment_code.first() != Some(&LETTER_P) {
            return Err(Error::Format("Incorrect format version"));
        }

        PublicCode::try_from_bytes(&payment_code[1..])
    }
}

/// The notification mode to be used with a payment code.
pub enum NotificationMode<'a> {
    BasicTransaction(BasicTransaction<'a>),
    Bitmessage(Bitmessage<'a>),
    BloomMultisig(BloomMultisig<'a>),
}

/// Represents the on-chain notification mode and provides functionality for constructing
/// an on-chain notification message.
pub struct BasicTransaction<'a>(&'a PublicCode);

impl<'a> BasicTransaction<'a> {
    /// Derives the notification pubkey belonging to this payment code. This is exposed in case the
    /// consumer needs the notification pubkey for any reason, such as for manual blinding operations.
    /// Under normal circumstances, it is sufficient to use `notification_address`.
    pub fn notification_pubkey(&self) -> Result<PublicKey, Error> {
        let child = self
            .0
            .xpub
            .ckd_pub(&self.0.curve, ChildNumber::from_normal_idx(0)?);
        let key = child?.public_key;

        Ok(key)
    }

    /// Derives the notification address belonging to this payment code.
    pub fn notification_address(&self, segwit: bool) -> Result<Address, Error> {
        let key = self.notification_pubkey()?;

        if segwit {
            Address::p2wpkh(&key, self.0.network).map_err(Error::Address)
        } else {
            Ok(Address::p2pkh(&key, self.0.network))
        }
    }

    /// Generates output scripts (scriptpubkeys) for a v1 notification transaction. Both outputs must
    /// be included and the notification input and key must not be easily associated with the sender.
    pub fn make_notification_scripts(
        &self,
        sender_code: &PublicCode,
        notification_sk: &PrivateKey,
        notification_utxo: &bitcoin::OutPoint,
    ) -> Result<(Script, Script), Error> {
        make_v1_notification_scripts(sender_code, self.0, notification_sk, notification_utxo)
    }

    /// Derives the notification private key belonging to a private payment code.
    /// Needed if spending from a notification address etc.
    pub fn notification_privkey(private_code: &PrivateCode) -> Result<PrivateKey, Error> {
        private_code.child(0).map_err(Error::Bip32)
    }
}

/// Represents the Bitmessage notification mode and provides functionality for constructing
/// a Bitmessage notification message.
pub struct Bitmessage<'a> {
    code: &'a PublicCode,
    preferences: &'a BitMessagePreference,
}

impl<'a> Bitmessage<'a> {
    /// Makes the required parameters needed to send a bitmessage to a recipient.
    pub fn make_send_params(&self, n: u32) -> Result<BitMessageSendParams, Error> {
        let signing_key = self
            .code
            .xpub
            .ckd_pub(&self.code.curve, ChildNumber::from_normal_idx(0)?)?
            .ckd_pub(&self.code.curve, ChildNumber::from_normal_idx(0)?)?
            .public_key;

        let encryption_key = self
            .code
            .xpub
            .ckd_pub(&self.code.curve, ChildNumber::from_normal_idx(0)?)?
            .ckd_pub(&self.code.curve, ChildNumber::from_normal_idx(n)?)?
            .public_key;

        Ok(BitMessageSendParams {
            encryption_key,
            signing_key,
            stream_number: self.preferences.stream_number,
            version: self.preferences.version,
        })
    }
}

/// Represents the "bloom-multisig" (also known as v2) notification mode and provides functionality for
/// constructing an on-chain notification message.
pub struct BloomMultisig<'a>(&'a PublicCode);

impl<'a> BloomMultisig<'a> {
    /// Generates a bloom filter identifier to watch for. This is what the receiving party
    /// should add to their bloom filter in order to notice bloom filter type notifications.
    pub fn identifier(&self) -> Vec<u8> {
        let hashed_payment_code = sha256::Hash::hash(&self.0.as_bytes());
        let mut identifier = Vec::with_capacity(33);
        identifier.push(0x02_u8);
        identifier.extend_from_slice(&hashed_payment_code);
        identifier
    }

    /// Generates output scripts for a v2 notification transaction. The change key belongs to the **sender's wallet**.
    pub fn notification_params(
        &self,
        sender_code: &PublicCode,
        notification_sk: &PrivateKey,
        notification_utxo: &bitcoin::OutPoint,
        change_pk: &PublicKey,
    ) -> Result<(Script, Script), Error> {
        use bitcoin::blockdata::opcodes::all as opcode;
        use bitcoin::blockdata::script::Builder;

        let op_return_script = {
            let notification_pk = self.0.child(0)?;
            let blinding_factor =
                blinding_factor(notification_sk, &notification_pk, notification_utxo)?;

            let mut sender_code = sender_code.as_bytes();
            blind_payment_code(&mut sender_code, &blinding_factor);

            Script::new_op_return(&sender_code)
        };

        // lexicographic ordering
        let serialized_pk = change_pk.serialize();
        let identifier = self.identifier();
        let (first_push, second_push) = match &serialized_pk.cmp(&identifier) {
            std::cmp::Ordering::Less => (serialized_pk, identifier),
            _ => (identifier, serialized_pk),
        };

        let multisig_script = Builder::new()
            .push_opcode(opcode::OP_PUSHNUM_1)
            .push_slice(&first_push)
            .push_slice(&second_push)
            .push_opcode(opcode::OP_PUSHNUM_2)
            .push_opcode(opcode::OP_CHECKMULTISIG)
            .into_script();

        Ok((multisig_script, op_return_script))
    }
}

/// A set of Bitmessage preferences indicated by the receiving party.
#[derive(Debug)]
pub struct BitMessagePreference {
    pub version: u8,
    pub stream_number: u8,
}

/// Contains all the parameters needed to send a bitmessage to a recipient.
#[derive(Debug)]
pub struct BitMessageSendParams {
    pub signing_key: PublicKey,
    pub encryption_key: PublicKey,
    pub version: u8,
    pub stream_number: u8,
}

/// Calculates a secret point given a private key and a public key.
fn secret_point(sk: &PrivateKey, mut pk: PublicKey) -> Result<[u8; 32], secp256k1::Error> {
    let _ = pk.key.mul_assign(&Secp256k1::new(), &sk.to_bytes())?;
    let mut point = [0_u8; 32];
    point.copy_from_slice(&pk.key.serialize()[1..]);
    Ok(point)
}

/// Calculates a shared secret given a secret point.
fn shared_secret(secret_point: [u8; 32]) -> Result<[u8; 32], secp256k1::Error> {
    let hash = sha256::Hash::hash(&secret_point);
    secp256k1::SecretKey::from_slice(&hash)?;
    Ok(hash.into_inner())
}

/// Calculates a blinding factor. The operation is symmetrical, therefore the key combination can be:
/// 1. notification private key, designated public key
/// 2. designated private key, notification public key
pub fn blinding_factor(
    sk: &PrivateKey,
    pk: &PublicKey,
    utxo: &bitcoin::OutPoint,
) -> Result<[u8; 64], secp256k1::Error> {
    let mut pk = pk.key;
    pk.mul_assign(&Secp256k1::new(), &sk.to_bytes())?;

    let mut encoded_utxo = Vec::with_capacity(36);
    encoded_utxo.extend_from_slice(&utxo.txid);
    encoded_utxo.extend_from_slice(&u32_to_le_bytes(utxo.vout));

    use bitcoin::hashes::{self, sha512, HashEngine, Hmac};
    let mut hmac = hashes::hmac::HmacEngine::<sha512::Hash>::new(&encoded_utxo);
    hmac.input(&pk.serialize()[1..]);
    let hash = Hmac::<sha512::Hash>::from_engine(hmac);

    Ok(hash.into_inner())
}

/// Blinds a payment code using a byte mask.
fn blind_payment_code(bytes: &mut [u8; PAYMENT_CODE_BIN_LENGTH], mask: &[u8; 64]) {
    bytes
        .iter_mut()
        .skip(3)
        .zip(mask.iter())
        .for_each(|(a, b)| {
            *a ^= b;
        });
}

/// Generates outputs for a notification transaction. Both outputs must be included and the notification
/// input and key must not be easily associated with the sender.
fn make_v1_notification_scripts(
    sender_code: &PublicCode,
    recipient_code: &PublicCode,
    notification_sk: &PrivateKey,
    notification_utxo: &bitcoin::OutPoint,
) -> Result<(Script, Script), Error> {
    let notification_pk = recipient_code.child(0)?;
    let blinding_factor = blinding_factor(notification_sk, &notification_pk, notification_utxo)?;

    let mut sender_code = sender_code.as_bytes();
    blind_payment_code(&mut sender_code, &blinding_factor);

    Ok((
        bitcoin::Script::new_p2pkh(&notification_pk.pubkey_hash()),
        bitcoin::Script::new_op_return(&sender_code),
    ))
}

/// Attempts to extract the designated input and its associated pubkey from a transaction.
/// A designated input is the first input whose scriptsig or witness exposes a pubkey
/// (designated pubkey).
fn find_designated(tx: &Transaction) -> Option<(PublicKey, OutPoint)> {
    use bitcoin::blockdata::script::Instruction::PushBytes;

    fn from_scriptsig(tx: &Transaction) -> Option<(PublicKey, OutPoint)> {
        tx.input
            .iter()
            .filter_map(|tx_in| {
                let first_pk = tx_in
                    .script_sig
                    .instructions()
                    .filter_map(|op| match op {
                        Ok(PushBytes(bytes)) => PublicKey::from_slice(bytes).ok(),
                        _ => None,
                    })
                    .next();

                first_pk.map(|pk| (pk, tx_in.previous_output))
            })
            .next()
    }

    fn from_witness(tx: &Transaction) -> Option<(PublicKey, OutPoint)> {
        tx.input
            .iter()
            .filter_map(|tx_in| {
                let first_pk = tx_in
                    .witness
                    .iter()
                    .filter_map(|witness| PublicKey::from_slice(witness).ok())
                    .next();

                first_pk.map(|pk| (pk, tx_in.previous_output))
            })
            .next()
    }

    from_scriptsig(tx).or_else(|| from_witness(tx))
}

/// Represents an error as pertaining to BIP47 operations.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum Error {
    Format(&'static str),
    Base58(base58::Error),
    Bip32(bip32::Error),
    Ecdsa(secp256k1::Error),
    UnsupportedVersion,
    Notification(&'static str),
    Address(address::Error),
}

impl From<bip32::Error> for Error {
    fn from(error: bip32::Error) -> Self {
        Error::Bip32(error)
    }
}

impl From<secp256k1::Error> for Error {
    fn from(error: secp256k1::Error) -> Self {
        Error::Ecdsa(error)
    }
}

impl From<bitcoin::util::key::Error> for Error {
    fn from(error: bitcoin::util::key::Error) -> Self {
        match error {
            bitcoin::util::key::Error::Base58(error) => Error::Base58(error),
            bitcoin::util::key::Error::Secp256k1(error) => Error::Ecdsa(error),
        }
    }
}

impl From<address::Error> for Error {
    fn from(error: address::Error) -> Self {
        Error::Address(error)
    }
}

fn u32_to_le_bytes(x: u32) -> [u8; 4] {
    let b1: u8 = (x & 0xff) as u8;
    let b2: u8 = ((x >> 8) & 0xff) as u8;
    let b3: u8 = ((x >> 16) & 0xff) as u8;
    let b4: u8 = ((x >> 24) & 0xff) as u8;
    [b1, b2, b3, b4]
}

#[cfg(test)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
mod tests {
    use std::fmt::Write;
    use std::str::FromStr;

    extern crate bitcoin;

    use bitcoin::hashes::{self, hex::HexIterator};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::util::psbt::serialize::Deserialize;
    use bitcoin::{Address, Network, PrivateKey, PublicKey};

    use super::{
        blind_payment_code, blinding_factor, find_designated, make_v1_notification_scripts,
        secret_point, NotificationMode, PrivateCode, PublicCode,
    };

    const ALICE_BIP32_SEED: &str = "64dca76abc9c6f0cf3d212d248c380c4622c8f93b2c425ec6a5567fd5db57e10d3e6f94a2f6af4ac2edb8998072aad92098db73558c323777abf5bd1082d970a";
    const ALICE_PAYMENT_CODE: &str = "PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA";
    const ALICE_NOTIFICATION_ADDRESS: &str = "1JDdmqFLhpzcUwPeinhJbUPw4Co3aWLyzW";
    const ALICE_a0: &str = "8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c";
    const ALICE_A0: &str = "0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683";

    const BOB_BIP32_SEED: &str = "87eaaac5a539ab028df44d9110defbef3797ddb805ca309f61a69ff96dbaa7ab5b24038cf029edec5235d933110f0aea8aeecf939ed14fc20730bba71e4b1110";
    const BOB_PAYMENT_CODE: &str = "PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97";
    const BOB_NOTIFICATION_ADDRESS: &str = "1ChvUUvht2hUQufHBXF8NgLhW8SwE2ecGV";

    const BOB_b0: &str = "04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b";
    const BOB_B0: &str = "024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8";
    const BOB_b1: &str = "6bfa917e4c44349bfdf46346d389bf73a18cec6bc544ce9f337e14721f06107b";
    const BOB_B1: &str = "03e092e58581cf950ff9c8fc64395471733e13f97dedac0044ebd7d60ccc1eea4d";
    const BOB_b2: &str = "46d32fbee043d8ee176fe85a18da92557ee00b189b533fce2340e4745c4b7b8c";
    const BOB_B2: &str = "029b5f290ef2f98a0462ec691f5cc3ae939325f7577fcaf06cfc3b8fc249402156";

    // Secret points are essentially public EC points but the first byte (used for compression)
    // has been ommitted here because that is the way the test vectors were originally written.
    const SECRET_POINT_0: &str = "f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef";
    const SECRET_POINT_1: &str = "adfb9b18ee1c4460852806a8780802096d67a8c1766222598dc801076beb0b4d";
    const SECRET_POINT_2: &str = "79e860c3eb885723bb5a1d54e5cecb7df5dc33b1d56802906762622fa3c18ee5";

    const BOB_ADDR_0: &str = "141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK";
    const BOB_ADDR_1: &str = "12u3Uued2fuko2nY4SoSFGCoGLCBUGPkk6";
    const BOB_ADDR_2: &str = "1FsBVhT5dQutGwaPePTYMe5qvYqqjxyftc";

    const ALICE_DESIGNATED_PRIVATE_KEY: &str =
        "Kx983SRhAZpAhj7Aac1wUXMJ6XZeyJKqCxJJ49dxEbYCT4a1ozRD";
    // The endianess here is reversed with respect to the test vector value for easier parsing.
    // (was "86f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c01000000")
    const ALICE_NOTIFICATION_UTXO: &str =
        "9c6000d597c5008f7bfc2618aed5e4a6ae57677aab95078aae708e1cab11f486:1";
    const NOTIFICATION_BLINDING_FACTOR: &str = "be6e7a4256cac6f4d4ed4639b8c39c4cb8bece40010908e70d17ea9d77b4dc57f1da36f2d6641ccb37cf2b9f3146686462e0fa3161ae74f88c0afd4e307adbd5";
    const ALICE_BLINDED_CODE: &str = "010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000";

    const NOTIFICATION_SCRIPT: &str = "76a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac";
    const OP_RETURN_SCRIPT: &str = "6a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0cf048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b00000000000000000000000000";

    const NOTIFICATION_TX: &str = "\
    010000000186f411ab1c8e70ae8a0795ab7a6757aea6e4d5ae1826fc7b8f00c597d500609c010000006b48304502210\
    0ac8c6dbc482c79e86c18928a8b364923c774bfdbd852059f6b3778f2319b59a7022029d7cc5724e2f41ab1fcfc0ba5\
    a0d4f57ca76f72f19530ba97c860c70a6bf0a801210272d83d8a1fa323feab1c085157a0791b46eba34afb8bfbfaeb3\
    a3fcc3f2c9ad8ffffffff0210270000000000001976a9148066a8e7ee82e5c5b9b7dc1765038340dc5420a988ac1027\
    000000000000536a4c50010002063e4eb95e62791b06c50e1a3a942e1ecaaa9afbbeb324d16ae6821e091611fa96c0c\
    f048f607fe51a0327f5e2528979311c78cb2de0d682c61e1180fc3d543b0000000000000000000000000000000000";

    fn from_hex(hex: &str) -> Vec<u8> {
        HexIterator::new(hex)
            .unwrap()
            .filter_map(|a| a.ok())
            .collect()
    }

    fn to_hex(bytes: &[u8]) -> Option<String> {
        let mut s = String::with_capacity(2 * bytes.len());
        for byte in bytes {
            write!(s, "{:02x}", byte).ok()?;
        }
        Some(s)
    }

    #[test]
    fn test_payment_code_from_seed() {
        let seed: Vec<u8> = hashes::hex::FromHex::from_hex(ALICE_BIP32_SEED).unwrap();
        let private = PrivateCode::from_seed(&seed, 0, Network::Bitcoin).unwrap();
        let public = private.v1_public_code(None);

        assert_eq!(public.to_string(), ALICE_PAYMENT_CODE);
    }

    #[test]
    fn test_payment_code_from_text() {
        let payment_code = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();

        assert_eq!(payment_code.to_string(), ALICE_PAYMENT_CODE);
    }

    #[test]
    fn test_notification_address() {
        // Alice
        let alice_payment_code = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();
        if let NotificationMode::BasicTransaction(onchain) = alice_payment_code.notification_mode()
        {
            assert_eq!(
                onchain.notification_address(false).unwrap(),
                Address::from_str(ALICE_NOTIFICATION_ADDRESS).unwrap()
            );
        } else {
            panic!("should not be using bitmessage here");
        }

        // Bob
        let bob_payment_code = PublicCode::from_wif(BOB_PAYMENT_CODE).unwrap();

        if let NotificationMode::BasicTransaction(onchain) = bob_payment_code.notification_mode() {
            assert_eq!(
                onchain.notification_address(false).unwrap(),
                Address::from_str(BOB_NOTIFICATION_ADDRESS).unwrap()
            );
        } else {
            panic!("should not be using bitmessage here");
        }
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_ecdh_params() {
        // Alice
        let alice_seed: Vec<u8> = hashes::hex::FromHex::from_hex(ALICE_BIP32_SEED).unwrap();
        let alice_private = PrivateCode::from_seed(&alice_seed, 0, Network::Bitcoin).unwrap();

        let alice_a0 = alice_private.child(0).unwrap();
        let alice_A0 = PublicKey::from_private_key(&Secp256k1::new(), &alice_a0);
        assert_eq!(ALICE_a0, alice_a0.key.to_string());
        assert_eq!(ALICE_A0, alice_A0.key.to_string());

        // Bob
        let bob_seed: Vec<u8> = hashes::hex::FromHex::from_hex(BOB_BIP32_SEED).unwrap();
        let bob_private = PrivateCode::from_seed(&bob_seed, 0, Network::Bitcoin).unwrap();

        let bob_b0 = bob_private.child(0).unwrap();
        let bob_b1 = bob_private.child(1).unwrap();
        let bob_b2 = bob_private.child(2).unwrap();
        let bob_B0 = PublicKey::from_private_key(&Secp256k1::new(), &bob_b0);
        let bob_B1 = PublicKey::from_private_key(&Secp256k1::new(), &bob_b1);
        let bob_B2 = PublicKey::from_private_key(&Secp256k1::new(), &bob_b2);
        assert_eq!(BOB_b0, bob_b0.key.to_string());
        assert_eq!(BOB_b1, bob_b1.key.to_string());
        assert_eq!(BOB_b2, bob_b2.key.to_string());
        assert_eq!(BOB_B0, bob_B0.key.to_string());
        assert_eq!(BOB_B1, bob_B1.key.to_string());
        assert_eq!(BOB_B2, bob_B2.key.to_string());
    }

    #[test]
    #[allow(non_snake_case)]
    fn test_ecdh_params_from_public() {
        let alice_public = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();

        let alice_A0 = alice_public.child(0).unwrap();
        assert_eq!(ALICE_A0, alice_A0.key.to_string());
    }

    #[test]
    fn test_secret_point_alice_side() {
        let sk = PrivateKey::from_slice(&from_hex(&ALICE_a0), bitcoin::Network::Bitcoin).unwrap();
        let pk0 = PublicKey::from_slice(&from_hex(&BOB_B0)).unwrap();
        let pk1 = PublicKey::from_slice(&from_hex(&BOB_B1)).unwrap();
        let pk2 = PublicKey::from_slice(&from_hex(&BOB_B2)).unwrap();

        let sp0 = secret_point(&sk, pk0).unwrap();
        let sp1 = secret_point(&sk, pk1).unwrap();
        let sp2 = secret_point(&sk, pk2).unwrap();

        assert_eq!(SECRET_POINT_0, to_hex(&sp0).unwrap());
        assert_eq!(SECRET_POINT_1, to_hex(&sp1).unwrap());
        assert_eq!(SECRET_POINT_2, to_hex(&sp2).unwrap());
    }

    #[test]
    fn test_secret_point_bob_side() {
        let pk = PublicKey::from_slice(&from_hex(&ALICE_A0)).unwrap();
        let sk0 = PrivateKey::from_slice(&from_hex(&BOB_b0), bitcoin::Network::Bitcoin).unwrap();
        let sk1 = PrivateKey::from_slice(&from_hex(&BOB_b1), bitcoin::Network::Bitcoin).unwrap();
        let sk2 = PrivateKey::from_slice(&from_hex(&BOB_b2), bitcoin::Network::Bitcoin).unwrap();

        let sp0 = secret_point(&sk0, pk).unwrap();
        let sp1 = secret_point(&sk1, pk).unwrap();
        let sp2 = secret_point(&sk2, pk).unwrap();

        assert_eq!(SECRET_POINT_0, to_hex(&sp0).unwrap());
        assert_eq!(SECRET_POINT_1, to_hex(&sp1).unwrap());
        assert_eq!(SECRET_POINT_2, to_hex(&sp2).unwrap());
    }

    #[test]
    fn test_payment_address_alice_side() {
        let alice_seed: Vec<u8> =
            bitcoin::hashes::hex::FromHex::from_hex(ALICE_BIP32_SEED).unwrap();
        let alice_private = PrivateCode::from_seed(&alice_seed, 0, Network::Bitcoin).unwrap();

        let bob_public = PublicCode::from_wif(BOB_PAYMENT_CODE).unwrap();

        let addr_0 = bob_public.address(&alice_private, 0, false).unwrap();
        let addr_1 = bob_public.address(&alice_private, 1, false).unwrap();
        let addr_2 = bob_public.address(&alice_private, 2, false).unwrap();

        assert_eq!(BOB_ADDR_0, addr_0.to_string());
        assert_eq!(BOB_ADDR_1, addr_1.to_string());
        assert_eq!(BOB_ADDR_2, addr_2.to_string());
    }

    #[test]
    fn test_payment_address_bob_side() {
        let alice_public = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();

        let bob_seed: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(BOB_BIP32_SEED).unwrap();
        let bob_private = PrivateCode::from_seed(&bob_seed, 0, Network::Bitcoin).unwrap();

        let addr_0 = bob_private.address(&alice_public, 0, false).unwrap();
        let addr_1 = bob_private.address(&alice_public, 1, false).unwrap();
        let addr_2 = bob_private.address(&alice_public, 2, false).unwrap();

        assert_eq!(BOB_ADDR_0, addr_0.to_string());
        assert_eq!(BOB_ADDR_1, addr_1.to_string());
        assert_eq!(BOB_ADDR_2, addr_2.to_string());
    }

    #[test]
    fn test_blinding() {
        let bob_public = PublicCode::from_wif(BOB_PAYMENT_CODE).unwrap();

        let alice_designated_sk = PrivateKey::from_wif(&ALICE_DESIGNATED_PRIVATE_KEY).unwrap();
        let pk = bob_public.child(0).unwrap();
        let utxo = bitcoin::OutPoint::from_str(ALICE_NOTIFICATION_UTXO).unwrap();

        let blinding_factor = blinding_factor(&alice_designated_sk, &pk, &utxo).unwrap();
        assert_eq!(
            NOTIFICATION_BLINDING_FACTOR,
            to_hex(&blinding_factor).unwrap()
        );

        let alice_public = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();
        let mut alice_bytes = alice_public.as_bytes();

        // Blind
        blind_payment_code(&mut alice_bytes, &blinding_factor);
        assert_eq!(to_hex(&alice_bytes).unwrap(), ALICE_BLINDED_CODE);

        // Unblind
        blind_payment_code(&mut alice_bytes, &blinding_factor);
        assert_eq!(
            PublicCode::try_from_bytes(&alice_bytes)
                .unwrap()
                .to_string(),
            ALICE_PAYMENT_CODE
        );
    }

    #[test]
    fn test_make_v1_notification_scripts() {
        let alice_public = PublicCode::from_wif(ALICE_PAYMENT_CODE).unwrap();
        let bob_public = PublicCode::from_wif(BOB_PAYMENT_CODE).unwrap();

        let alice_notification_private_key =
            PrivateKey::from_wif(ALICE_DESIGNATED_PRIVATE_KEY).unwrap();
        let alice_notification_utxo = bitcoin::OutPoint::from_str(ALICE_NOTIFICATION_UTXO).unwrap();

        let (notification_script, op_return_script) = make_v1_notification_scripts(
            &alice_public,
            &bob_public,
            &alice_notification_private_key,
            &alice_notification_utxo,
        )
        .unwrap();

        assert_eq!(
            to_hex(notification_script.as_bytes()).unwrap(),
            NOTIFICATION_SCRIPT
        );

        assert_eq!(
            to_hex(op_return_script.as_bytes()).unwrap(),
            OP_RETURN_SCRIPT
        );
    }

    #[test]
    fn test_find_designated_in_notification() {
        // p2pkh
        let tx = bitcoin::Transaction::deserialize(&from_hex(NOTIFICATION_TX)).unwrap();

        let expected_designated_input =
            bitcoin::OutPoint::from_str(ALICE_NOTIFICATION_UTXO).unwrap();
        let expected_designated_pk = PrivateKey::from_wif(ALICE_DESIGNATED_PRIVATE_KEY)
            .map(|sk| sk.public_key(&Secp256k1::new()))
            .unwrap();

        let (actual_pk, actual_input) = find_designated(&tx).unwrap();

        assert_eq!(expected_designated_input, actual_input);
        assert_eq!(expected_designated_pk, actual_pk);

        // p2wpkh (these are not in the original test vectors)
        let expected_segwit_input = bitcoin::OutPoint::from_str(
            "1fda2a46b57af5ddb087294ed7f98c218311474336fb92638881db71ec6039f6:91",
        )
        .unwrap();
        let expected_segwit_address =
            Address::from_str("bc1qpflfdc2fu9e4udp788h0pdrehjf202h75m86s0");

        let segwit_tx = bitcoin::Transaction::deserialize(&from_hex("01000000000101f63960ec71db81886392fb3643471183218cf9d74e2987b0ddf57ab5462ada1f5b000000000000000001aa7c0100000000001600145866fcd59dcdabf34dee30abd4c9924ec387830402483045022100f31b80da6c620a2f9d12b65b2010d962390f57560169dde54368b4b5cf122b11022001915d1693cac8bea16e28d941ed7a34eec3bb231a475f5d1616cf5af3f13329012102df62d69f610e2bf7463480a8dd52b96aefeeb3111d66e5e579a0971bc41ce77200000000")).unwrap();

        let (actual_segwit_pk, actual_segwit_input) = find_designated(&segwit_tx).unwrap();

        assert_eq!(expected_segwit_input, actual_segwit_input);
        assert_eq!(
            expected_segwit_address,
            Address::p2wpkh(&actual_segwit_pk, Network::Bitcoin)
        );
    }

    #[test]
    fn test_extract_payment_code_from_tx() {
        let tx = bitcoin::Transaction::deserialize(&from_hex(NOTIFICATION_TX)).unwrap();

        let bob_seed: Vec<u8> = bitcoin::hashes::hex::FromHex::from_hex(BOB_BIP32_SEED).unwrap();
        let bob_private = PrivateCode::from_seed(&bob_seed, 0, Network::Bitcoin).unwrap();

        let alice_public = PublicCode::from_notification(&bob_private, None, &tx).unwrap();
        assert_eq!(
            PublicCode::from_wif(ALICE_PAYMENT_CODE)
                .unwrap()
                .to_string(),
            alice_public.to_string()
        );
    }
}
