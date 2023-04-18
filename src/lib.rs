/*	Copyright (c) 2022, 2023 Laurenz Werner
	
	This file is part of Dawn.
	
	Dawn is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	Dawn is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with Dawn.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::convert::TryFrom;
use dawn_stdlib::*;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jshort;
use serde::{Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};

// Error return macros
macro_rules! error {
	($env: expr, $a: expr) => {
		let error = Error { status: $a };
		return $env.new_string(serde_json::to_string(&error).expect("Could not return error")).expect("Could not create new java string");
	}
}

#[derive(Serialize)]
struct Error<'a> {
	status: &'a str
}

#[derive(Serialize)]
struct SendMessage<'a> {
	status: &'a str,
	new_pfs_key: &'a str,
	mdc: &'a str,
	ciphertext: &'a str
}

#[derive(Serialize)]
struct ParseMessage<'a> {
	status: &'a str,
	msg_type: u8,
	msg_text: &'a str,
	msg_bytes: &'a str,
	new_pfs_key: &'a str,
	mdc: &'a str
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_sendMsg<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	msg_type: jshort,
	msg_string: JString<'local>,
	msg_bytes: JByteArray<'local>,
	remote_pubkey_kyber: JByteArray<'local>,
	own_seckey_sig: JByteArray<'local>,
	pfs_key: JByteArray<'local>
) -> JString<'local> {
	
	let msg_type = match u8::try_from(msg_type) {
		Ok(n) => n,
		Err(_) => { error!(env, &format!("Invalid message type provided: {}", msg_type)); },
	};
	
	let msg_string = env.get_string(&msg_string);
	if msg_string.is_err() { error!(env, "Could not get java variable: msg_string"); }
	let msg_string: String = msg_string.unwrap().into();
	let msg_string = match msg_string.as_str() {
		"" => None,
		_ => Some(msg_string.as_str())
	};
	
	let msg_bytes = env.convert_byte_array(&msg_bytes);
	if msg_bytes.is_err() { error!(env, "Could not get java variable: msg_bytes"); }
	let msg_bytes = msg_bytes.unwrap();
	let msg_bytes = match msg_bytes.len() {
		0 => None,
		_ => Some(msg_bytes.as_slice())
	};
	
	let remote_pubkey_kyber = env.convert_byte_array(&remote_pubkey_kyber);
	if remote_pubkey_kyber.is_err() { error!(env, "Could not get java variable: remote_pubkey_kyber"); }
	let remote_pubkey_kyber = remote_pubkey_kyber.unwrap();
	
	let own_seckey_sig = env.convert_byte_array(&own_seckey_sig);
	if own_seckey_sig.is_err() { error!(env, "Could not get java variable: own_seckey_sig"); }
	let own_seckey_sig = own_seckey_sig.unwrap();
	
	let pfs_key = env.convert_byte_array(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key = pfs_key.unwrap();
	
	let (new_pfs_key, mdc, ciphertext) = match send_msg((msg_type, msg_string, msg_bytes), &remote_pubkey_kyber, &own_seckey_sig, &pfs_key) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	let send_message = SendMessage {
		status: "ok",
		new_pfs_key: &BASE64.encode(&new_pfs_key),
		mdc: &mdc,
		ciphertext: &BASE64.encode(&ciphertext)
	};
	
	let send_message_json = match serde_json::to_string(&send_message) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	send_message_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_parseMsg<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	msg_ciphertext: JByteArray<'local>,
	own_seckey_kyber: JByteArray<'local>,
	remote_pubkey_sig: JByteArray<'local>,
	pfs_key: JByteArray<'local>
) -> JString<'local> {
	
	let msg_ciphertext = env.convert_byte_array(&msg_ciphertext);
	if msg_ciphertext.is_err() { error!(env, "Could not get java variable: msg_ciphertext"); }
	let msg_ciphertext = msg_ciphertext.unwrap();
	
	let own_seckey_kyber = env.convert_byte_array(&own_seckey_kyber);
	if own_seckey_kyber.is_err() { error!(env, "Could not get java variable: own_seckey_kyber"); }
	let own_seckey_kyber = own_seckey_kyber.unwrap();
	
	let remote_pubkey_sig = env.convert_byte_array(&remote_pubkey_sig);
	if remote_pubkey_sig.is_err() { error!(env, "Could not get java variable: remote_pubkey_sig"); }
	let remote_pubkey_sig = remote_pubkey_sig.unwrap();
	let remote_pubkey_sig = match remote_pubkey_sig.len() {
		0 => None,
		_ => Some(remote_pubkey_sig.as_slice())
	};
	
	let pfs_key = env.convert_byte_array(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key = pfs_key.unwrap();
	
	let ((msg_type, msg_text, msg_bytes), new_pfs_key, mdc) = match parse_msg(&msg_ciphertext, &own_seckey_kyber, remote_pubkey_sig, &pfs_key) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	
	let msg_text = match msg_text {
		Some(text) => text,
		None => "".to_string()
	};
	
	let msg_bytes = match msg_bytes {
		Some(bytes) => BASE64.encode(&bytes),
		None => "".to_string()
	};
	
	let parse_message = ParseMessage {
		status: "ok",
		msg_type: msg_type,
		msg_text: &msg_text,
		msg_bytes: &msg_bytes,
		new_pfs_key: &BASE64.encode(&new_pfs_key),
		mdc: &mdc,
	};
	
	let parse_message_json = match serde_json::to_string(&parse_message) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	parse_message_json
}
