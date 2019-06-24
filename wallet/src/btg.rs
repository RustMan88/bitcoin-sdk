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

fn signature_hash(tx: &Transaction, input_index: usize, script_pubkey: &Script, sighash_u32: u32) -> H256 {
    assert!(input_index < tx.inputs.len());

    let (sighash, anyone_can_pay) = SigHashType::from_u32(sighash_u32).split_anyonecanpay_flag();
    // Special-case sighash_single bug because this is easy enough.
    if sighash == SigHashType::Single && input_index >= tx.outputs.len() {
        let v = [1, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0];
        return H256::from(v);
    }

    // Build tx to sign
    let mut tx_tmp = Transaction {
        version: tx.version,
        lock_time: tx.lock_time,
        inputs: vec![],
        outputs: vec![],
    };

    // Add all inputs necessary..
    if anyone_can_pay {
        tx_tmp.inputs.push(TransactionInput {
            previous_output: tx.inputs[input_index].previous_output.clone(),
            script_sig: script_pubkey.to_bytes(),
            sequence: tx.inputs[input_index].sequence,
            script_witness: vec![],
        })
    } else {
        tx_tmp.inputs = Vec::with_capacity(tx.inputs.len());

        for n in 0..tx.inputs.len() {
            let input = &tx.inputs[n];
            tx_tmp.inputs.push(TransactionInput {
                previous_output: input.previous_output.clone(),
                script_sig: if n == input_index { script_pubkey.to_bytes() } else { Script::from("").to_bytes() },
                sequence: if n != input_index && (sighash == SigHashType::Single || sighash == SigHashType::None) { 0 } else { input.sequence },
                script_witness: vec![],
            });
        }
    }

    // ..then all outputs
    tx_tmp.outputs = match sighash {
        SigHashType::All => tx.outputs.clone(),
        SigHashType::Single => {
            let output_iter = tx.outputs.iter()
                .take(input_index + 1)  // sign all outputs up to and including this one, but erase
                .enumerate()            // all of them except for this one
                .map(|(n, out)| if n == input_index { out.clone() } else { TransactionOutput::default() });
            output_iter.collect()
        }
        SigHashType::None => vec![],
        _ => unreachable!()
    };

    let mut tx_raw = serialization::serialize(&tx_tmp).take();
    tx_raw.extend([1, 0, 0, 0].iter());

    return bitcrypto::dhash256(&tx_raw);
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

/*    let vouts: Vec<_> = req_vouts.iter().map(|out| {
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
        return res;
    }).collect();*/

    Ok(vouts)
}

pub fn create_rawtx(vins: Vec<TxInputReq>, vouts: Vec<TxOutput>) -> Result<Transaction, Error> {

    // to make lock_time work at least one input must have sequnce < SEQUENCE_FINAL
    let lock_time = 0u32;
    let default_sequence = if lock_time != 0 { chain::constants::SEQUENCE_FINAL - 1 } else { chain::constants::SEQUENCE_FINAL };

    let mut inputs = vec![];
    for i in 0..vins.len(){
        let input = &vins[i];
        inputs.push(TransactionInput {
            previous_output: OutPoint {
                hash: input.txid.parse::<H256>().map_err(|_| Error::TxidParseError)?,
                index: input.index,
            },
            script_sig: Bytes::new(),
            sequence: default_sequence,
            script_witness: vec![],
        })
    }
    // prepare inputs
   /* let inputs: Vec<_> = vins.into_iter().map(|input| {
        TransactionInput {
            previous_output: OutPoint {
                hash: input.txid.parse::<H256>().map_err(|| Error::TxidParseError)?,
                index: input.index,
            },
            script_sig: Bytes::new(),
            sequence: default_sequence,
            script_witness: vec![],
        }
    }).collect();*/

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
        version: 0,
        inputs,
        outputs,
        lock_time,
    })
}

pub fn sign_rawtx(tx :&mut Transaction,accounts:Vec<Account>)->Result<Bytes,Error>{
   if tx.inputs.len() == 0 || tx.inputs.len() != accounts.len(){
       return Err(Error::GreateRawTxError)
   }

    for i in 0..tx.inputs.len() {
        let account = &accounts[i];
        match account.address.kind {
            AddressType::P2PKH => {
                let pk_script = ScriptBuilder::build_p2pkh(&account.address.hash);
                let mut serialized_sig = account.kp.private().sign(
                    &signature_hash(&tx, i, &pk_script, 0x1)).map_err(|_| Error::SignRawTxError)?;
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

    Ok(serialization::serialize(tx))
}


/*
pub fn sign_tx(vins: Vec<TxInputReq>, vouts: Vec<TxOutputReq>, accounts: HashMap<String, Account>) -> Result<Transaction, Error> {
    let total_out = vouts.iter().fold(0, |acc, output| acc + output.value);
    let total_in = vins.iter().fold(0, |acc, input| acc + input.credit);

    if total_in < total_out {
        return Err(Error::NotEnoughAmount);
    }

    //1. 创建交易模板
    let mut tx = Transaction {
        version: 0,
        lock_time: 0,
        inputs: Vec::new(),
        outputs: Vec::new(),
    };

    //3. 填充 vouts
    for i in 0..vouts.len() {
        let vout = &vouts[i];
        // dest output

        //let account = accounts.get(&vout.address).ok_or(Error::CustomError("don't find key".to_string()))?;
        let to_addr = Address::from_str(&vout.address)?;
        let output = TransactionOutput {
            value: vout.value,
            script_pubkey: ScriptBuilder::build_p2pkh(&to_addr.hash).to_bytes(),
        };
        tx.outputs.push(output);
    }
    //2.填充 vins

    for i in 0..vins.len() {
        let vin = &vins[i];

        let txid = vin.txid.clone();
        let mut input = TransactionInput {
            previous_output: OutPoint { hash: txid.parse::<H256>().map_err(|| Err(Error::TxidParseError))?, index: vin.index },
            script_sig: Bytes::new(),
            sequence: constants::SEQUENCE_FINAL,
            script_witness: Vec::new(),
        };

        let account = accounts.get(&vin.address).ok_or(Error::CustomError("don't find key".to_string()))?;
        match account.address.kind {
            AddressType::P2PKH => {
                let pk_script = ScriptBuilder::build_p2pkh(&account.address.hash);
                let mut serialized_sig = account.kp.private().sign(
                    &signature_hash(&tx, i, &pk_script, 0x1)).map_err(|_| Error::CustomError("address error".to_string()))?;
                let mut serialized_sig_vec = serialized_sig.to_vec();
                serialized_sig_vec.push(0x1);

                let script = ScriptBuilder::default()
                    .push_bytes(&serialized_sig_vec)
                    .push_bytes(&account.kp.public())
                    .into_script();

                input.script_sig = script.to_bytes();
            }
            _ => return Err(Error::NotSupportedAddressFormError),
        }

        tx.inputs.push(input);
    }



    Ok(tx)
}
*/

