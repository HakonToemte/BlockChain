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

#[derive(Serialize, Debug, Deserialize)]
pub struct App {
    pub blocks: Vec<Block>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Block {
    pub id: u32,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: String,
    pub data: String,
    pub signature: String,
}

impl App {
    pub fn new() -> Self {
        Self {
            blocks : Vec::new()
        }
    }
    pub fn genesis(block: Block) -> Self {
        Self {
            blocks : vec![block]
        }
    }
    pub fn add_block(&mut self, state: &mut State, data: String, signature: String, hash: String) { 
        let mut previous_block = state.previous_app.blocks.last().unwrap();
        if self.blocks.len() != 0 as usize{
            previous_block = &self.blocks.last().unwrap();
        }
        let id = previous_block.id +1;
        let mut time = Time::new();
        time.ree_time();
        let next_block = Block::new(id as u32,&previous_block.hash,&data, &signature, &hash, time);
        self.blocks.push(next_block);

    }
}

impl Block {
    pub fn new(id: u32, previous_hash: &str, data: &str, signature: &str, hash: &str, time:Time) -> Self {
        Self {
            id: id,
            previous_hash: String::from(previous_hash), // hexstring
            data: String::from(data), // readable text
            hash: String::from(hash), // hexstring
            signature: String::from(signature), // hexstring
            timestamp: format!("{}", time),
        }
    }
}

pub struct State {
    pub key_pair: signature::Ed25519KeyPair,
    pub previous_app: App,
}

impl Default for State {
    fn default() -> Self {
        Self {
            key_pair: gen_key().unwrap(),                // for ED25519 key encryption
            previous_app: App::genesis(Block::new(0_u32, "genesis", 
                "genesis", "signature genesis", "026A64FB40C946B5ABEE2573702828694D5B4C43", Time::new())),
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

fn serialize_app(mut app_buffer: &mut [u8], app: &App) -> Result<u32>{
    // Convert the Block to a JSON string.
    let serialized = serde_json::to_string(app).unwrap();
    // writes serialized Block to buffer, so it can be viewed in normal world
    if (app_buffer.len() < serialized.as_bytes().len()){
        trace_println!("BUFFER TOO SHORT");
        return Err(Error::new(ErrorKind::ShortBuffer));
    }
    let len = app_buffer.write(serialized.as_bytes()).unwrap();
    trace_println!("length of App = {}", len);
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
    let mut p0 = unsafe { params.0.as_memref().unwrap() }; //  available memory for App
    let mut p1 = unsafe { params.1.as_memref().unwrap() }; // all texts to hash, each data entry is separated with a ";" (u8=59)
    let mut p2 = unsafe { params.2.as_value().unwrap()}; // length of App object
    let mut input = p1.buffer();
    let mut app = App::new();
    let mut iter = input.split(|num| num == &59_u8).peekable(); // loops through all data entries, creating a block for each
    let mut previous_hash = &state.previous_app.blocks.last().unwrap().hash;
    while let Some(data_entry) = iter.next() {
        if iter.peek() == None{
            continue;
        }
        let mut hash_vector: Vec<u8> = hash(previous_hash.to_string(), data_entry);
        let string = String::from_utf8(data_entry.to_vec()).unwrap();
        // Create digital signature using private key
        let mut signature_buffer = [0u8; SIGNATURE_SIZE];
        sign(state, &mut hash_vector, &mut signature_buffer).unwrap();
        let signature= byte_vector_to_hexstring(&mut signature_buffer.to_vec());
        // Create next block
        app.add_block(state, string, signature, byte_vector_to_hexstring(&mut hash_vector));

        // serializes the block and sets p2 to its length
        previous_hash = &app.blocks.last().unwrap().hash;


    }
    let len = serialize_app(p0.buffer(), &app).unwrap();
    p2.set_a(len);
    state.previous_app = app;
    Ok(())
}
fn sign(state: &mut State, plain_text: &mut [u8], signature_buffer: &mut [u8]) -> Result<()> {
    let sig = state.key_pair.sign(plain_text);
    signature_buffer.clone_from_slice(sig.as_ref());

    Ok(())
}
fn hash(previous_hash: String, input: &[u8]) -> Vec<u8>{
    let digestop = Digest::allocate(AlgorithmId::Sha256).unwrap();
    let mut length_for_hash = 0_u32;
    digestop.update(input);
    //while let Some(word_as_bytes) = iter.next() {
    //    digestop.update(word_as_bytes);
    //}
    let previous_hash_bytes = previous_hash.as_bytes();
    let mut output = &mut [0u8; 32];
    match digestop.do_final(&previous_hash_bytes, output) {
        Err(e) => Err(e),
        Ok(hash_length) => {
            length_for_hash = hash_length as u32;
            //trace_println!("hash length {}", length_for_hash);
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
const TA_DATA_SIZE: u32 =   32*32 * 1024;
const TA_STACK_SIZE: u32 =  2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is a hello world example.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Hello World TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));