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
use jni::objects::{JClass, JString, JByteArray};
use hex::{encode, decode};
use crate::{Error, InitCrypto, KyberKeys, CurveKeys, SignKeys, SymKey, GenId, TempId, NextId, GenMdc, SecurityNumber, Hash, Timestamp, MultiTimestamp};
use crate::error;

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_initCrypto<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let ((own_pubkey_kyber, own_seckey_kyber), (own_pubkey_curve, own_seckey_curve), (own_pubkey_kyber_for_salt, own_seckey_kyber_for_salt), (own_pubkey_curve_for_salt, own_seckey_curve_for_salt), id) = init_crypto();
	let init_crypto = InitCrypto {
		status: "ok",
		id: &id,
		own_pubkey_kyber: &encode(own_pubkey_kyber),
		own_seckey_kyber: &encode(own_seckey_kyber),
		own_pubkey_curve: &encode(own_pubkey_curve),
		own_seckey_curve: &encode(own_seckey_curve),
		own_pubkey_kyber_for_salt: &encode(own_pubkey_kyber_for_salt),
		own_seckey_kyber_for_salt: &encode(own_seckey_kyber_for_salt),
		own_pubkey_curve_for_salt: &encode(own_pubkey_curve_for_salt),
		own_seckey_curve_for_salt: &encode(own_seckey_curve_for_salt)
	};
	
	let init_crypto_json = match serde_json::to_string(&init_crypto) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	init_crypto_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_kyberKeygen<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let (own_pubkey_kyber, own_seckey_kyber) = kyber_keygen();
	let kyber_keygen = KyberKeys {
		status: "ok",
		own_pubkey_kyber: &encode(own_pubkey_kyber),
		own_seckey_kyber: &encode(own_seckey_kyber)
	};
	
	let kyberkeys_json = match serde_json::to_string(&kyber_keygen) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	kyberkeys_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_curveKeygen<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let (own_pubkey_curve, own_seckey_curve) = curve_keygen();
	let curve_keygen = CurveKeys {
		status: "ok",
		own_pubkey_curve: &encode(own_pubkey_curve),
		own_seckey_curve: &encode(own_seckey_curve)
	};
	
	let curvekeys_json = match serde_json::to_string(&curve_keygen) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	curvekeys_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_signKeygen<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let (own_pubkey_sig, own_seckey_sig) = sign_keygen();
	let sign_keygen = SignKeys {
		status: "ok",
		own_pubkey_sig: &encode(own_pubkey_sig),
		own_seckey_sig: &encode(own_seckey_sig)
	};
	
	let signkeys_json = match serde_json::to_string(&sign_keygen) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	signkeys_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_symKeygen<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let sym_key = SymKey {
		status: "ok",
		key: &encode(sym_key_gen()),
	};
	
	let sym_key_json = match serde_json::to_string(&sym_key) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	sym_key_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_genId<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let id = GenId {
		status: "ok",
		id: &id_gen(),
	};
	
	let id_json = match serde_json::to_string(&id) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	id_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_getTempId<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	id: JString<'local>
) -> JString<'local> {
	
	let id = env.get_string(&id);
	if id.is_err() { error!(env, "Could not get java variable: id"); }
	let id: String = id.unwrap().into();
	
	let id = match get_temp_id(&id) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Encountered an error while trying to derive temporary id: {}", err)); }
	};
	
	let temp_id = TempId {
		status: "ok",
		id: &id
	};
	
	let temp_id_json = match serde_json::to_string(&temp_id) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	temp_id_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_getCustomTempId<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	id: JString<'local>,
	modifier: JString<'local>
) -> JString<'local> {
	
	let id = env.get_string(&id);
	if id.is_err() { error!(env, "Could not get java variable: id"); }
	let id: String = id.unwrap().into();
	
	let modifier = env.get_string(&modifier);
	if modifier.is_err() { error!(env, "Could not get java variable: modifier"); }
	let modifier: String = modifier.unwrap().into();
	
	let id = match get_custom_temp_id(&id, &modifier) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Encountered an error while trying to derive temporary id: {}", err)); }
	};
	
	let temp_id = TempId {
		status: "ok",
		id: &id
	};
	
	let temp_id_json = match serde_json::to_string(&temp_id) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	temp_id_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_getNextId<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	id: JString<'local>,
	salt: JString<'local>
) -> JString<'local> {
	
	let id = env.get_string(&id);
	if id.is_err() { error!(env, "Could not get java variable: id"); }
	let id: String = id.unwrap().into();
	
	let salt = env.get_string(&salt);
	if salt.is_err() { error!(env, "Could not get java variable: salt"); }
	let salt: String = salt.unwrap().into();
	
	let next_id = match get_next_id(&id, &salt) {
		Ok(res) => res,
		Err(err) => { error!(env, &format!("Encountered an error while trying to derive next id: {}", err)); }
	};
	
	let next_id = NextId {
		status: "ok",
		id: &next_id
	};
	
	let next_id_json = match serde_json::to_string(&next_id) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	next_id_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_genMdc<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	mdc_seed: JString<'local>,
	temp_id: JString<'local>
) -> JString<'local> {
	
	let mdc_seed = env.get_string(&mdc_seed);
	if mdc_seed.is_err() { error!(env, "Could not get java variable: mdc_seed"); }
	let mdc_seed: String = mdc_seed.unwrap().into();
	
	let temp_id = env.get_string(&temp_id);
	if temp_id.is_err() { error!(env, "Could not get java variable: temp_id"); }
	let temp_id: String = temp_id.unwrap().into();
	
	let mdc = GenMdc {
		status: "ok",
		mdc: &predictable_mdc_gen(&mdc_seed, &temp_id),
	};
	
	let mdc_json = match serde_json::to_string(&mdc) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	mdc_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_genPredictableMdc<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let mdc = GenMdc {
		status: "ok",
		mdc: &mdc_gen(),
	};
	
	let mdc_json = match serde_json::to_string(&mdc) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	mdc_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_deriveSecurityNumber<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	key_a: JString<'local>,
	key_b: JString<'local>
) -> JString<'local> {
	
	let key_a = env.get_string(&key_a);
	if key_a.is_err() { error!(env, "Could not get java variable: key_a"); }
	let key_a: String = key_a.unwrap().into();
	let key_a = match decode(key_a) {
		Ok(res) => res,
		Err(_) => { error!(env, "key_a invalid"); }
	};
	
	let key_b = env.get_string(&key_b);
	if key_b.is_err() { error!(env, "Could not get java variable: key_b"); }
	let key_b: String = key_b.unwrap().into();
	let key_b = match decode(key_b) {
		Ok(res) => res,
		Err(_) => { error!(env, "key_b invalid"); }
	};
	
	let number = match derive_security_number(&key_a, &key_b) {
		Ok(res) => res,
		Err(error) => { error!(env, &format!("Could not derive security number: {}", error)); }
	};
	
	let security_number = SecurityNumber {
		status: "ok",
		number: &number
	};
	
	let security_number_json = match serde_json::to_string(&security_number) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	security_number_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_hashString<'local> (
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	input: JString<'local>,
) -> JString<'local> {
	
	let input = env.get_string(&input);
	if input.is_err() { error!(env, "Could not get java variable: input"); }
	let input: String = input.unwrap().into();
	let input = input.as_bytes();
	
	let hash = hash(input);
	
	let hash = Hash {
		status: "ok",
		hash: &encode(hash)
	};
	
	let hash_json = match serde_json::to_string(&hash) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	hash_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_hashBytes<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
	input: JByteArray<'local>,
) -> JString<'local> {
	
	let input = env.convert_byte_array(input);
	if input.is_err() { error!(env, "Could not get java variable: input"); }
	let input = input.unwrap();
	
	let hash = hash(&input);
	
	let hash = Hash {
		status: "ok",
		hash: &encode(hash)
	};
	
	let hash_json = match serde_json::to_string(&hash) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	hash_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_getCurrentTimestamp<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let timestamp = get_current_timestamp();
	if timestamp.is_err() { error!(env, "Could not get timestamp"); }
	
	let timestamp = Timestamp {
		status: "ok",
		timestamp: &timestamp.unwrap()
	};
	
	let timestamp_json = match serde_json::to_string(&timestamp) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	timestamp_json
}

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_getAllTimestampsSince<'local>(
	mut env: JNIEnv<'local>,
	_class: JClass<'local>,
	timestamp: JString<'local>
) -> JString<'local> {
	
	let timestamp = env.get_string(&timestamp);
	if timestamp.is_err() { error!(env, "Could not get java variable: timestamp"); }
	let timestamp: String = timestamp.unwrap().into();
	
	let timestamps = get_all_timestamps_since(&timestamp);
	if timestamps.is_err() { error!(env, &format!("Could not calculate timestamps: {}", timestamps.unwrap_err())); }
	
	let timestamps = MultiTimestamp {
		status: "ok",
		timestamps: timestamps.unwrap()
	};
	
	let timestamps_json = match serde_json::to_string(&timestamps) {
		Ok(res) => match env.new_string(res) {
			Ok(jstring) => jstring,
			Err(_) => { error!(env, "Could not create new java string"); }
		}
		Err(_) => { error!(env, "Could not serialize json"); }
	};
	timestamps_json
}
