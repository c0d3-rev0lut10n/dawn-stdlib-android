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

use dawn_stdlib::*;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use hex::{encode, decode};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use crate::{Error, GenInitRequest, ParseInitRequest, AcceptInitRequest, ParseInitResponse};
use crate::error;

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_genInitRequest<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	remote_pubkey_kyber: JString<'local>,
	remote_pubkey_curve: JString<'local>,
	own_pubkey_sig: JString<'local>,
	own_seckey_sig: JString<'local>,
	name: JString<'local>,
	comment: JString<'local>
) -> JString<'local> {
	
	let remote_pubkey_kyber = env.get_string(&remote_pubkey_kyber);
	if remote_pubkey_kyber.is_err() { error!(env, "Could not get java variable: remote_pubkey_kyber"); }
	let remote_pubkey_kyber: String = remote_pubkey_kyber.unwrap().into();
	let remote_pubkey_kyber = match decode(remote_pubkey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "remote_pubkey_kyber invalid"); }
	};
	
	let remote_pubkey_curve = env.get_string(&remote_pubkey_curve);
	if remote_pubkey_curve.is_err() { error!(env, "Could not get java variable: remote_pubkey_curve"); }
	let remote_pubkey_curve: String = remote_pubkey_curve.unwrap().into();
	let remote_pubkey_curve = match decode(remote_pubkey_curve) {
		Ok(res) => res,
		Err(_) => { error!(env, "remote_pubkey_curve invalid"); }
	};
	
	let own_pubkey_sig = env.get_string(&own_pubkey_sig);
	if own_pubkey_sig.is_err() { error!(env, "Could not get java variable: own_pubkey_sig"); }
	let own_pubkey_sig: String = own_pubkey_sig.unwrap().into();
	let own_pubkey_sig = match decode(own_pubkey_sig) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_pubkey_sig invalid"); }
	};
	
	let own_seckey_sig = env.get_string(&own_seckey_sig);
	if own_seckey_sig.is_err() { error!(env, "Could not get java variable: own_seckey_sig"); }
	let own_seckey_sig: String = own_seckey_sig.unwrap().into();
	let own_seckey_sig = match decode(own_seckey_sig) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_sig invalid"); }
	};
	
	let name = env.get_string(&name);
	if name.is_err() { error!(env, "Could not get java variable: name"); }
	let name: String = name.unwrap().into();
	
	let comment = env.get_string(&comment);
	if comment.is_err() { error!(env, "Could not get java variable: comment"); }
	let comment: String = comment.unwrap().into();
	
	let ((own_pubkey_kyber, own_seckey_kyber), (own_pubkey_curve, own_seckey_curve), pfs_key, id, mdc, ciphertext) = match gen_init_request(&remote_pubkey_kyber, &remote_pubkey_curve, &own_pubkey_sig, &own_seckey_sig, &name, &comment) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Could not generate init request: {}", err)); }
	};
	
	let gen_init_request = GenInitRequest {
		status: "ok",
		own_pubkey_kyber: &encode(own_pubkey_kyber),
		own_seckey_kyber: &encode(own_seckey_kyber),
		own_pubkey_curve: &encode(own_pubkey_curve),
		own_seckey_curve: &encode(own_seckey_curve),
		pfs_key: &encode(pfs_key),
		id: &id,
		mdc: &mdc,
		ciphertext: &BASE64.encode(ciphertext)
	};
	
	let gen_init_request_json = match serde_json::to_string(&gen_init_request) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	gen_init_request_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_parseInitRequest<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	ciphertext: JByteArray<'local>,
	own_seckey_kyber: JString<'local>,
	own_seckey_curve: JString<'local>
) -> JString<'local> {
	
	let ciphertext = env.convert_byte_array(ciphertext);
	if ciphertext.is_err() { error!(env, "Could not get java variable: ciphertext"); }
	let ciphertext = ciphertext.unwrap();
	
	let own_seckey_kyber = env.get_string(&own_seckey_kyber);
	if own_seckey_kyber.is_err() { error!(env, "Could not get java variable: own_seckey_kyber"); }
	let own_seckey_kyber: String = own_seckey_kyber.unwrap().into();
	let own_seckey_kyber = match decode(own_seckey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_kyber invalid"); }
	};
	
	let own_seckey_curve = env.get_string(&own_seckey_curve);
	if own_seckey_curve.is_err() { error!(env, "Could not get java variable: own_seckey_curve"); }
	let own_seckey_curve: String = own_seckey_curve.unwrap().into();
	let own_seckey_curve = match decode(own_seckey_curve) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_curve invalid"); }
	};
	
	let (id, mdc, remote_pubkey_kyber, remote_pubkey_sig, new_pfs_key, name, comment) = match parse_init_request(&ciphertext, &own_seckey_kyber, &own_seckey_curve) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Could not parse init request: {}", err)); }
	};
	
	let parse_init_request = ParseInitRequest {
		status: "ok",
		id: &id,
		mdc: &mdc,
		remote_pubkey_kyber: &encode(remote_pubkey_kyber),
		remote_pubkey_sig: &encode(remote_pubkey_sig),
		new_pfs_key: &encode(new_pfs_key),
		name: &name,
		comment: &comment
	};
	
	let parse_init_request_json = match serde_json::to_string(&parse_init_request) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	parse_init_request_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_acceptInitRequest<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	own_seckey_sig: JString<'local>,
	own_pubkey_sig: JString<'local>,
	remote_pubkey_kyber: JString<'local>,
	pfs_key: JString<'local>
) -> JString<'local> {
	
	let own_seckey_sig = env.get_string(&own_seckey_sig);
	if own_seckey_sig.is_err() { error!(env, "Could not get java variable: own_seckey_sig"); }
	let own_seckey_sig: String = own_seckey_sig.unwrap().into();
	let own_seckey_sig = match decode(own_seckey_sig) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_sig invalid"); }
	};
	
	let own_pubkey_sig = env.get_string(&own_pubkey_sig);
	if own_pubkey_sig.is_err() { error!(env, "Could not get java variable: own_pubkey_sig"); }
	let own_pubkey_sig: String = own_pubkey_sig.unwrap().into();
	let own_pubkey_sig = match decode(own_pubkey_sig) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_pubkey_sig invalid"); }
	};
	
	let remote_pubkey_kyber = env.get_string(&remote_pubkey_kyber);
	if remote_pubkey_kyber.is_err() { error!(env, "Could not get java variable: remote_pubkey_kyber"); }
	let remote_pubkey_kyber: String = remote_pubkey_kyber.unwrap().into();
	let remote_pubkey_kyber = match decode(remote_pubkey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "remote_pubkey_kyber invalid"); }
	};
	
	let pfs_key = env.get_string(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key: String = pfs_key.unwrap().into();
	let pfs_key = match decode(pfs_key) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_key invalid"); }
	};
	
	let (new_pfs_key, (own_pubkey_kyber, own_seckey_kyber), mdc, ciphertext) = match accept_init_request(&own_pubkey_sig, &own_seckey_sig, &remote_pubkey_kyber, &pfs_key) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Could not create init accept message: {}", err)); }
	};
	
	let accept_init_request = AcceptInitRequest {
		status: "ok",
		new_pfs_key: &encode(new_pfs_key),
		own_pubkey_kyber: &encode(own_pubkey_kyber),
		own_seckey_kyber: &encode(own_seckey_kyber),
		mdc: &mdc,
		ciphertext: &BASE64.encode(ciphertext)
	};
	
	let accept_init_request_json = match serde_json::to_string(&accept_init_request) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	accept_init_request_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_parseInitResponse<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	ciphertext: JByteArray<'local>,
	own_seckey_kyber: JString<'local>,
	pfs_key: JString<'local>
) -> JString<'local> {
	
	let ciphertext = env.convert_byte_array(ciphertext);
	if ciphertext.is_err() { error!(env, "Could not get java variable: ciphertext"); }
	let ciphertext = ciphertext.unwrap();
	
	let own_seckey_kyber = env.get_string(&own_seckey_kyber);
	if own_seckey_kyber.is_err() { error!(env, "Could not get java variable: own_seckey_kyber"); }
	let own_seckey_kyber: String = own_seckey_kyber.unwrap().into();
	let own_seckey_kyber = match decode(own_seckey_kyber) {
		Ok(res) => res,
		Err(_) => { error!(env, "own_seckey_kyber invalid"); }
	};
	
	let pfs_key = env.get_string(&pfs_key);
	if pfs_key.is_err() { error!(env, "Could not get java variable: pfs_key"); }
	let pfs_key: String = pfs_key.unwrap().into();
	let pfs_key = match decode(pfs_key) {
		Ok(res) => res,
		Err(_) => { error!(env, "pfs_key invalid"); }
	};
	
	let (remote_pubkey_kyber, remote_pubkey_sig, new_pfs_key, mdc) = match parse_init_response(&ciphertext, &own_seckey_kyber, &pfs_key) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("init response could not be parsed: {}", err)); }
	};
	
	let parse_init_response = ParseInitResponse {
		status: "ok",
		remote_pubkey_kyber: &encode(remote_pubkey_kyber),
		remote_pubkey_sig: &encode(remote_pubkey_sig),
		new_pfs_key: &encode(new_pfs_key),
		mdc: &mdc
	};
	
	let parse_init_response_json = match serde_json::to_string(&parse_init_response) {
		Ok(res) => match env.new_string(res) {
			Ok(res) => res,
			Err(_) => { error!(env, "Could not create new java string"); }
		},
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	parse_init_response_json
}
