// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.
#![no_main]

use ring::signature::KeyPair;
use ring::{rand, signature};

use optee_utee::Time;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Digest, AlgorithmId, Asymmetric, OperationMode, Result};
use optee_utee::{TransientObject, TransientObjectType};
use serde::{Deserialize, Serialize};
use std::io::Write;
use proto::{Command};


const SIGNATURE_SIZE: usize = 64;
#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub id: u32,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: String,
    pub data: String,
    pub signature: String,
}
impl Block {
    pub fn new(id: u32, previous_hash: &str, data: &str, signature: &str, hash: &str, time: &str) -> Self {
        Self {
            id: id,
            previous_hash: String::from(previous_hash), // hexstring
            data: String::from(data), // readable text
            hash: String::from(hash), // hexstring
            signature: String::from(signature), // hexstring
            timestamp: String::from(time),
        }
    }
}

pub struct State {
    pub key_pair: signature::Ed25519KeyPair,
    pub previous_block: Block,
}
impl State{
    pub fn add_block(&mut self, data: String, signature: String, hash: String, time: &str) -> Block { 
        let previous_block = &self.previous_block;
        let id = previous_block.id +1;
        let next_block = Block::new(id as u32,&previous_block.hash,&data, &signature, &hash, time);
        return next_block

    }
}
impl Default for State {
    fn default() -> Self {
        Self {
            key_pair: gen_key().unwrap(),                // for ED25519 key encryption
            previous_block: Block::new(0_u32, "genesis", "genesis", "signature genesis", "026A64FB40C946B5ABEE2573702828694D5B4C43", "GenesisTimeStamp",)
        }
    }
}

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters, _sess_ctx: &mut State) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session(_sess_ctx: &mut State) {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}
fn gen_key() -> Result<signature::Ed25519KeyPair> {
    //trace_println!("genkey");
     // Generate a key pair in PKCS#8 (v2) format.
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = match signature::Ed25519KeyPair::generate_pkcs8(&rng) {
        Ok(bytes) => bytes,
        Err(e) => {
            trace_println!("[+] error: {:?}", e);
            return Err(Error::new(ErrorKind::Generic));
        }
    };
    let key_pair = match signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()) {
        Ok(key_pair) => key_pair,
        Err(e) => {
            trace_println!("[+] error: {:?}", e);
            return Err(Error::new(ErrorKind::Generic));
        }
    };
    Ok(key_pair)
}

fn serialize_block(mut block_buffer: &mut [u8], block: &Block) -> Result<u32>{
    // Convert the Block to a JSON string.
    let serialized = serde_json::to_string(block).unwrap();
    // writes serialized Block to buffer, so it can be viewed in normal world
    if (block_buffer.len() < serialized.as_bytes().len()){
        return Err(Error::new(ErrorKind::ShortBuffer));
    }
    let len = block_buffer.write(serialized.as_bytes()).unwrap();
    trace_println!("length of block = {}", len);
    Ok(len as u32)
}
fn get_public_key(state: &mut State, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() };
    let mut public_key_buffer = p0.buffer();
    // writes public key to buffer, so it can be viewed in normal world
    public_key_buffer.clone_from_slice(state.key_pair.public_key().as_ref());
    Ok(())
}

fn new_block(state: &mut State, params: &mut Parameters) -> Result<()> {
    let mut p0 = unsafe { params.0.as_memref().unwrap() }; //  available memory for Block
    let mut p1 = unsafe { params.1.as_memref().unwrap() }; // text to hash
    let mut p2 = unsafe { params.2.as_value().unwrap()}; // length of Block object
    let input = p1.buffer();
    let mut time = Time::new();
    time.ree_time();
    let time_string = format!("{}",time);
    let mut hash_vector: Vec<u8> = hash(state, input, &time_string);
    // Create digital signature using private key
    let mut signature_buffer = [0u8; SIGNATURE_SIZE];
    sign(state, &mut hash_vector, &mut signature_buffer).unwrap();
    let signature= byte_vector_to_hexstring(&mut signature_buffer.to_vec());
    // Create next block
    let next_block = state.add_block(String::from_utf8(input.to_vec()).unwrap(), signature, byte_vector_to_hexstring(&mut hash_vector),&time_string);

    // serializes the block and sets p2 to its length
    let len = serialize_block(p0.buffer(), &next_block).unwrap();
    p2.set_a(len);
    state.previous_block= next_block;
    Ok(())
}
fn sign(state: &mut State, plain_text: &mut [u8], signature_buffer: &mut [u8]) -> Result<()> {
    let sig = state.key_pair.sign(plain_text);
    signature_buffer.clone_from_slice(sig.as_ref());

    Ok(())
}
fn hash(state: &mut State, input: &mut [u8], time:&str) -> Vec<u8>{
    let digestop = Digest::allocate(AlgorithmId::Sha256).unwrap();
    let previous_hash = &state.previous_block.hash;
    let mut length_for_hash = 0_u32;
    let mut iter = input.split(|num| num == &32_u8).peekable();
    digestop.update(input);
    let previous_hash_bytes = previous_hash.as_bytes();
    let mut output = &mut [0u8; 32];
    match digestop.do_final(&previous_hash_bytes, output) {
        Err(e) => Err(e),
        Ok(hash_length) => {
            length_for_hash = hash_length as u32;
            Ok(())
        }
    };
    let mut res = output.to_vec();
    //trace_println!("result {:?}", res);
    res.truncate(length_for_hash as usize);
    return res;
}
fn byte_vector_to_hexstring(byte_vector: &mut Vec<u8>) -> String {
    let strs: Vec<String> = byte_vector.iter()
                               .map(|b| format!("{:02X}", b))
                               .collect();
    let hash_string = strs.join("");
    return hash_string
}
#[ta_invoke_command]
fn invoke_command(sess_ctx: &mut State,cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::GetPublicKey => {
            return get_public_key(sess_ctx, params);
        }
        Command::NewBlock => {
            return new_block(sess_ctx, params);
        }
        Command::Empty => {
            return Ok(());
        }
        _ => {
            return Err(Error::new(ErrorKind::BadParameters));
        }
    };
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 =   16*32 * 1024;
const TA_STACK_SIZE: u32 =  2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is a hello world example.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Hello World TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));