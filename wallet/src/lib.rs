
extern crate chain;
extern crate primitives;
extern crate script;
extern crate keys;
extern crate serialization;
extern crate bitcrypto;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate byteorder;
pub mod btg;

pub use keys::{Address, Public, Private, KeyPair, Type as AddressType};
pub use chain::{Transaction, TransactionInput, TransactionOutput, OutPoint};
pub use self::btg::Account;

use script::{Builder, Script,SignatureVersion, TransactionInputSigner};
use primitives::bytes::Bytes;

#[derive(Debug)]
pub enum Error {
    GreateRawTxError,
    NotFoundKeyError,
    SignRawTxError,
    NotSupportedAddressFormError,
    TxidParseError,
    AddressParseError,
    PrivKeyParseError,
    NotEnoughAmount,
    PrepareRawTxError,
    NotFoundAesKeyError,
    AesDecryptError,
    SerdeJsonError,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInputReq {
    pub txid: String,
    pub index: u32,
    pub address: String,
    pub credit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutputReq {
    pub address: String,
    pub value: u64,
}

