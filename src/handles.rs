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
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};
use hex::{encode, decode};
use crate::{Error, GenHandle, ParseHandle};
use crate::error;

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_genHandle<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	init_pubkey_kyber: JString<'local>,
	init_pubkey_curve: JString<'local>,
	init_pubkey_kyber_for_salt: JString<'local>,
	init_pubkey_curve_for_salt: JString<'local>,
	name: JString<'local>
) -> JString<'local> {
	
	let init_pubkey_kyber = env.get_string(&init_pubkey_kyber);
	if init_pubkey_kyber.is_err() { error!(env, "Could not get java variable: init_pubkey_kyber"); }
	let init_pubkey_kyber: String = init_pubkey_kyber.unwrap().into();
	let init_pubkey_kyber = match decode(init_pubkey_kyber) {
		Ok(bytes) => bytes,
		Err(_) => { error!(env, "init_pubkey_kyber invalid"); }
	};
	
	let init_pubkey_curve = env.get_string(&init_pubkey_curve);
	if init_pubkey_curve.is_err() { error!(env, "Could not get java variable: init_pubkey_curve"); }
	let init_pubkey_curve: String = init_pubkey_curve.unwrap().into();
	let init_pubkey_curve = match decode(init_pubkey_curve) {
		Ok(bytes) => bytes,
		Err(_) => { error!(env, "init_pubkey_curve invalid"); }
	};
	let init_pubkey_kyber_for_salt = env.get_string(&init_pubkey_kyber_for_salt);
	if init_pubkey_kyber_for_salt.is_err() { error!(env, "Could not get java variable: init_pubkey_kyber_for_salt"); }
	let init_pubkey_kyber_for_salt: String = init_pubkey_kyber_for_salt.unwrap().into();
	let init_pubkey_kyber_for_salt = match decode(init_pubkey_kyber_for_salt) {
		Ok(bytes) => bytes,
		Err(_) => { error!(env, "init_pubkey_kyber_for_salt invalid"); }
	};
	let init_pubkey_curve_for_salt = env.get_string(&init_pubkey_curve_for_salt);
	if init_pubkey_curve_for_salt.is_err() { error!(env, "Could not get java variable: init_pubkey_curve_for_salt"); }
	let init_pubkey_curve_for_salt: String = init_pubkey_curve_for_salt.unwrap().into();
	let init_pubkey_curve_for_salt = match decode(init_pubkey_curve_for_salt) {
		Ok(bytes) => bytes,
		Err(_) => { error!(env, "init_pubkey_curve_for_salt invalid"); }
	};
	
	let name = env.get_string(&name);
	if name.is_err() { error!(env, "Could not get java variable: name"); }
	let name: String = name.unwrap().into();
	
	let handle = GenHandle {
		status: "ok",
		handle: &BASE64.encode(gen_handle(&init_pubkey_kyber, &init_pubkey_curve, &init_pubkey_kyber_for_salt, &init_pubkey_curve_for_salt, &name))
	};
	
	let handle_json = match serde_json::to_string(&handle) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	handle_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_parseHandle<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
	handle: JByteArray<'local>
) -> JString<'local> {
	
	let handle = env.convert_byte_array(handle);
	if handle.is_err() { error!(env, "Could not get java variable: handle"); }
	let handle = handle.unwrap();
	
	let (init_pubkey_kyber, init_pubkey_curve, init_pubkey_kyber_for_salt, init_pubkey_curve_for_salt, name) = match parse_handle(handle) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Standard Library returned error: {}", err)); }
	};
	
	let parse_handle = ParseHandle {
		status: "ok",
		init_pk_kyber: &encode(init_pubkey_kyber),
		init_pk_curve: &encode(init_pubkey_curve),
		init_pk_kyber_for_salt: &encode(init_pubkey_kyber_for_salt),
		init_pk_curve_for_salt: &encode(init_pubkey_curve_for_salt),
		name: &name
	};
	
	let parse_handle_json = match serde_json::to_string(&parse_handle) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	parse_handle_json
}
