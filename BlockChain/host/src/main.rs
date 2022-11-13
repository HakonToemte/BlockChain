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
use ring::signature::KeyPair;
use ring::{rand, signature};

use optee_teec::{Context, Operation, ParamType, ParamTmpRef, Session, Uuid};
use optee_teec::{ParamNone, ParamValue};
use optee_teec::{Error, ErrorKind};
use serde::Deserialize;
//use chrono::Utc;
use proto::{UUID, Command};

const PUBLIC_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Deserialize)]
pub struct App {
    pub blocks: Vec<Block>,
}

#[derive(Debug, Deserialize)]
pub struct Block {
    pub id: u32,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: String,
    pub data: String,
    pub signature: String,
}
fn get_public_key(session: &mut Session, public_key_buffer:  &mut [u8]) -> optee_teec::Result<()> {
    let p0 = ParamTmpRef::new_output(public_key_buffer);
    let mut operation = Operation::new(0, p0 , ParamNone, ParamNone, ParamNone);

    session.invoke_command(Command::GetPublicKey as u32, &mut operation)?;
    Ok(())
}


fn new_block(session: &mut Session, app_buffer: &mut [u8], string_to_log: &str) -> optee_teec::Result<usize> {
    println!("string_to_log a??? : {}", string_to_log);
    let p0 = ParamTmpRef::new_output(app_buffer);
    let p1 = ParamTmpRef::new_input(string_to_log.as_bytes());
    let p2 = ParamValue::new(0, 0, ParamType::ValueInout);
    let mut operation = Operation::new(0, p0, p1, p2, ParamNone);

    session.invoke_command(Command::NewBlock as u32, &mut operation).unwrap();

    Ok(operation.parameters().2.a() as usize)
}

fn main() -> optee_teec::Result<()> {
    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();

    let mut session = ctx.open_session(uuid)?;
    let mut block_buffer = [0u8; 528]; // minne for å sende blockchainen 
    let mut public_key_buffer = [0u8; PUBLIC_KEY_SIZE]; // minne for å lese public key
    get_public_key(&mut session, &mut public_key_buffer)?;
    let mut data = get_test_input();

    for string_to_log in data{
        let buffer_length = new_block(&mut session, &mut block_buffer, &string_to_log)?;
        let block: Block = serde_json::from_slice(&block_buffer[..buffer_length]).unwrap();
        println!("Received Block: {:?}", block);
    }

    println!("Success");
    Ok(())
}







fn get_test_input() -> Vec<String>{
    let mut inputs = Vec::new();
    inputs.push(String::from("Testdata"));
    inputs.push(String::from("jeg sender info4"));
    inputs.push(String::from("her kommer det data"));
    inputs.push(String::from("1b24123123 123 99"));
    inputs.push(String::from("bla 010 lorem ipsum"));
    inputs.push(String::from("example information"));
    return inputs
}