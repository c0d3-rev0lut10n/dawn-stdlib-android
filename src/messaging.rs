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
use hex::{encode, decode};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use crate::{Error, SendMessage, ParseMessage, EncryptFile, DecryptFile};
use crate::error;

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_sendMsg<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	msg_type: jshort,
	msg_string: JString<'local>,
	msg_bytes: JByteArray<'local>,
	remote_pubkey_kyber: JString<'local>,
	own_seckey_sig: JString<'local>,
	pfs_key: JString<'local>,
	pfs_salt: JString<'local>
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
	
	let msg_bytes = env.convert_byte_array(msg_bytes);
	if msg_bytes.is_err() { error!(env, "Could not get java variable: msg_bytes"); }
	let msg_bytes = msg_bytes.unwrap();
	let msg_bytes = match msg_bytes.len() {
		0 => None,
		_ => Some(msg_bytes.as_slice())
	};
	
	let remote_pubkey_kyber = env.get_string(&remote_pubkey_kyber);
	if remote_pubkey_kyber.is_err() { error!(env, "Could not get java variable: remote_pubkey_kyber"); }
	let remote_pubkey_kyber: String = remote_pubkey_kyber.unwrap().into();
	let remote_pubkey_kyber = match decode(remote_pubkey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "remote_pubkey_kyber invalid"); }
	};
	
	let own_seckey_sig = env.get_string(&own_seckey_sig);
	if own_seckey_sig.is_err() { error!(env, "Could not get java variable: own_seckey_sig"); }
	let own_seckey_sig: String = own_seckey_sig.unwrap().into();
	let own_seckey_sig = match decode(own_seckey_sig) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_sig invalid"); }
	};
	
	let pfs_key = env.get_string(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key: String = pfs_key.unwrap().into();
	let pfs_key = match decode(pfs_key) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_key invalid"); }
	};
	
	let pfs_salt = env.get_string(&pfs_salt);
	if pfs_salt.is_err() { error!(env, "Could not get java variable: pfs_salt"); }
	let pfs_salt: String = pfs_salt.unwrap().into();
	let pfs_salt = match decode(pfs_salt) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_salt invalid"); }
	};
	
	let (new_pfs_key, mdc, ciphertext) = match send_msg((msg_type, msg_string, msg_bytes), &remote_pubkey_kyber, Some(&own_seckey_sig), &pfs_key, &pfs_salt) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	let send_message = SendMessage {
		status: "ok",
		new_pfs_key: &encode(new_pfs_key),
		mdc: &mdc,
		ciphertext: &BASE64.encode(ciphertext)
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
	own_seckey_kyber: JString<'local>,
	remote_pubkey_sig: JString<'local>,
	pfs_key: JString<'local>,
	pfs_salt: JString<'local>
) -> JString<'local> {
	
	let msg_ciphertext = env.convert_byte_array(msg_ciphertext);
	if msg_ciphertext.is_err() { error!(env, "Could not get java variable: msg_ciphertext"); }
	let msg_ciphertext = msg_ciphertext.unwrap();
	
	let own_seckey_kyber = env.get_string(&own_seckey_kyber);
	if own_seckey_kyber.is_err() { error!(env, "Could not get java variable: own_seckey_kyber"); }
	let own_seckey_kyber: String = own_seckey_kyber.unwrap().into();
	let own_seckey_kyber = match decode(own_seckey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_kyber invalid"); }
	};
	
	let remote_pubkey_sig = env.get_string(&remote_pubkey_sig);
	if remote_pubkey_sig.is_err() { error!(env, "Could not get java variable: remote_pubkey_sig"); }
	let remote_pubkey_sig: String = remote_pubkey_sig.unwrap().into();
	let optional_remote_pubkey_sig;
	let remote_pubkey_sig_decoded;
	if &remote_pubkey_sig == "" {
		optional_remote_pubkey_sig = None;
	}
	else {
		let remote_pubkey_sig_res = decode(remote_pubkey_sig);
		if remote_pubkey_sig_res.is_err() { error!(env, "remote_pubkey_sig invalid"); }
		remote_pubkey_sig_decoded = remote_pubkey_sig_res.unwrap();
		optional_remote_pubkey_sig = Some(remote_pubkey_sig_decoded.as_slice());
	}
	
	let pfs_key = env.get_string(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key: String = pfs_key.unwrap().into();
	let pfs_key = match decode(pfs_key) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_key invalid"); }
	};
	
	let pfs_salt = env.get_string(&pfs_salt);
	if pfs_salt.is_err() { error!(env, "Could not get java variable: pfs_salt"); }
	let pfs_salt: String = pfs_salt.unwrap().into();
	let pfs_salt = match decode(pfs_salt) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_salt invalid"); }
	};
	
	let ((msg_type, msg_text, msg_bytes), new_pfs_key, mdc) = match parse_msg(&msg_ciphertext, &own_seckey_kyber, optional_remote_pubkey_sig, &pfs_key, &pfs_salt) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	
	let msg_text = match msg_text {
		Some(text) => text,
		None => "".to_string()
	};
	
	let msg_bytes = match msg_bytes {
		Some(bytes) => BASE64.encode(bytes),
		None => "".to_string()
	};
	
	let parse_message = ParseMessage {
		status: "ok",
		msg_type,
		msg_text: &msg_text,
		msg_bytes: &msg_bytes,
		new_pfs_key: &encode(new_pfs_key),
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

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_encryptFile<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
	file: JByteArray<'local>,
) -> JString<'local> {
	
	let file = match env.convert_byte_array(&file) {
		Ok(res) => res,
		Err(_) => { error!(env, "Could not read file"); }
	};
	
	let (ciphertext, key) = match encrypt_file(&file) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	
	let enc_file = EncryptFile {
		status: "ok",
		key: &encode(key),
		ciphertext: &encode(ciphertext)
	};
	
	let enc_file_json = match serde_json::to_string(&enc_file) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	enc_file_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_decryptFile<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	ciphertext: JByteArray<'local>,
	key: JString<'local>
) -> JString<'local> {
	
	let ciphertext = match env.convert_byte_array(&ciphertext) {
		Ok(res) => res,
		Err(_) => { error!(env, "Could not read ciphertext"); }
	};
	
	let key = env.get_string(&key);
	if key.is_err() { error!(env, "Could not get java variable: key"); }
	let key: String = key.unwrap().into();
	let key = match decode(key) {
		Ok(res) => res,
		Err(_) => { error!(env, "key invalid"); }
	};
	
	let file = match decrypt_file(&ciphertext, &key) {
		Ok(res) => res,
		Err(err) => { error!(env, &err); }
	};
	
	let file = DecryptFile {
		status: "ok",
		file: &encode(file)
	};
	
	let file_json = match serde_json::to_string(&file) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	file_json
}
