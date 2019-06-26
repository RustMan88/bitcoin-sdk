use chain::{Transaction, TransactionInput, TransactionOutput, OutPoint, constants};
use super::{TxInputReq, TxOutputReq, Error};
use primitives::{hash::H256, bytes::Bytes};
use keys::{Address, Public, Private, KeyPair, Type as AddressType};
use script::{Script, ScriptType, ScriptAddress, ScriptWitness, Builder as ScriptBuilder, Opcode};
use std::{
    collections::HashMap,
};


#[derive(Debug)]
pub struct Account {
    pub kp: KeyPair,
    pub address: Address,
}

/// Transaction output of form "address": amount
#[derive(Debug, PartialEq)]
pub struct TransactionOutputWithAddress {
    /// Receiver' address
    pub address: Address,
    /// Amount in BTC
    pub amount: u64,
}

/// Trasaction output of form "data": serialized(output script data)
#[derive(Debug, PartialEq)]
pub struct TransactionOutputWithScriptData {
    /// Serialized script data
    pub script_data: Bytes,
}

/// Transaction output
#[derive(Debug, PartialEq)]
pub enum TxOutput {
    /// Of form address: amount
    Address(TransactionOutputWithAddress),
    /// Of form data: script_data_bytes
    ScriptData(TransactionOutputWithScriptData),
}

/// Hashtype of a transaction, encoded in the last byte of a signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum SigHashType {
    /// 0x1: Sign all outputs
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,

    /// 0x81: Sign all outputs but only this input
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means)
    SinglePlusAnyoneCanPay = 0x83,
}

impl SigHashType {
    /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
    fn split_anyonecanpay_flag(&self) -> (SigHashType, bool) {
        match *self {
            SigHashType::All => (SigHashType::All, false),
            SigHashType::None => (SigHashType::None, false),
            SigHashType::Single => (SigHashType::Single, false),
            SigHashType::AllPlusAnyoneCanPay => (SigHashType::All, true),
            SigHashType::NonePlusAnyoneCanPay => (SigHashType::None, true),
            SigHashType::SinglePlusAnyoneCanPay => (SigHashType::Single, true)
        }
    }

    /// Reads a 4-byte uint32 as a sighash type
    pub fn from_u32(n: u32) -> SigHashType {
        match n & 0x9f {
            // "real" sighashes
            0x01 => SigHashType::All,
            0x02 => SigHashType::None,
            0x03 => SigHashType::Single,
            0x81 => SigHashType::AllPlusAnyoneCanPay,
            0x82 => SigHashType::NonePlusAnyoneCanPay,
            0x83 => SigHashType::SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => SigHashType::AllPlusAnyoneCanPay,
            _ => SigHashType::All
        }
    }

    /// Converts to a u32
    pub fn as_u32(&self) -> u32 { *self as u32 }
}
use byteorder::{LittleEndian, WriteBytesExt};
fn signature_hash(tx: &Transaction, input_index: usize, script_pubkey: &Script, sighash_u32: u32) -> H256 {
    assert!(input_index < tx.inputs.len());

    let tx_raw = serialization::serialize(tx).take();
    let mut tx_raw_with_sighash = tx_raw.clone();
    // SIGHASH_ALL
    //tx_raw_with_sighash.extend([1, 0, 0, 0].iter());
    tx_raw_with_sighash.write_u32::<LittleEndian>(sighash_u32).unwrap();
    return bitcrypto::dhash256(&tx_raw_with_sighash);
}

pub fn prepare_rawtx(vins: Vec<TxInputReq>, req_vouts: Vec<TxOutputReq>) -> Result<Vec<TxOutput>, Error> {

    //检查入数量是否大于等于出数量
    let total_out = req_vouts.iter().fold(0, |acc, output| acc + output.value);
    let total_in = vins.iter().fold(0, |acc, input| acc + input.credit);

    if total_in < total_out {
        return Err(Error::NotEnoughAmount);
    }

    let mut vouts = vec![];
    for i in 0..req_vouts.len() {
        let out = &req_vouts[i];

        let addr  = out.address.parse::<Address>().map_err(|_| Error::AddressParseError)?;
        let res = match addr.kind {
            AddressType::P2PKH => {
                TxOutput::Address(TransactionOutputWithAddress {
                    address: addr,
                    amount: out.value,
                })
            }
            AddressType::P2SH => {
                TxOutput::ScriptData(TransactionOutputWithScriptData {
                    script_data: Bytes::new()
                })
            }
        };
        vouts.push(res)
    }

    if vouts.len() == 0 {
        return Err(Error::PrepareRawTxError)
    }


    Ok(vouts)
}

pub fn create_rawtx(vins: Vec<TxInputReq>, vouts: Vec<TxOutput>) -> Result<Transaction, Error> {

    // to make lock_time work at least one input must have sequnce < SEQUENCE_FINAL
    let lock_time = 0u32;
    let default_sequence = if lock_time != 0 { chain::constants::SEQUENCE_FINAL - 1 } else { chain::constants::SEQUENCE_FINAL };

    let mut inputs = vec![];
    for i in 0..vins.len(){
        let input = &vins[i];

        let addr_from  = input.address.parse::<Address>().map_err(|_| Error::AddressParseError)?;
        let script_from = match addr_from.kind {
            keys::Type::P2PKH => ScriptBuilder::build_p2pkh(&addr_from.hash),
            keys::Type::P2SH => ScriptBuilder::build_p2sh(&addr_from.hash),
        };

        inputs.push(TransactionInput {
            previous_output: OutPoint {
                hash: input.txid.parse::<H256>().map_err(|_| Error::TxidParseError)?.reversed(),
                index: input.index,
            },
            script_sig: script_from.to_bytes(),
            sequence: default_sequence,
            script_witness: vec![],
        })
    }

    // prepare outputs
    let outputs: Vec<_> = vouts.into_iter()
        .map(|output| match output {
            TxOutput::Address(with_address) => {
                let script = match with_address.address.kind {
                    keys::Type::P2PKH => ScriptBuilder::build_p2pkh(&with_address.address.hash),
                    keys::Type::P2SH => ScriptBuilder::build_p2sh(&with_address.address.hash),
                };

                TransactionOutput {
                    value: with_address.amount,
                    script_pubkey: script.to_bytes(),
                }
            }
            TxOutput::ScriptData(with_script_data) => {
                let script = ScriptBuilder::default()
                    .return_bytes(&*with_script_data.script_data)
                    .into_script();

                TransactionOutput {
                    value: 0,
                    script_pubkey: script.to_bytes(),
                }
            }
        }).collect();

    if inputs.len() == 0 || outputs.len() == 0 {
        return Err(Error::GreateRawTxError)
    }

    Ok(Transaction {
        version: 2,
        inputs,
        outputs,
        lock_time,
    })
}

pub fn sign_rawtx(tx :&mut Transaction,accounts:Vec<Account>)->Result<String,Error>{
   if tx.inputs.len() == 0 || tx.inputs.len() != accounts.len(){
       return Err(Error::GreateRawTxError)
   }

    for i in 0..tx.inputs.len() {
        let account = &accounts[i];
        match account.address.kind {
            AddressType::P2PKH => {
                let pk_script = ScriptBuilder::build_p2pkh(&account.address.hash);
                let sign_type:u32 = 0x1|0x40;
                let mut serialized_sig = account.kp.private().sign(
                    &signature_hash(&tx, i, &pk_script, sign_type)).map_err(|_| Error::SignRawTxError)?;
                let mut serialized_sig_vec = serialized_sig.to_vec();
                serialized_sig_vec.push(0x1);

                let script = ScriptBuilder::default()
                    .push_bytes(&serialized_sig_vec)
                    .push_bytes(&account.kp.public())
                    .into_script();

                tx.inputs[i].script_sig = script.to_bytes();
            },
            _ => return Err(Error::NotSupportedAddressFormError)
        }
    }

    println!("{:?}",tx);

    Ok(bytes_to_hex(&serialization::serialize(tx).take()))
}


pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut res = String::with_capacity(bytes.len() * 2);
    for byte in bytes.iter() {
        res.push_str(&format!("{:02x}", byte));
    }
    res
}

