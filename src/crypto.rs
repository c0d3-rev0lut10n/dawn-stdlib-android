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
use crate::{Error, InitCrypto, GenId};
use crate::error;

#[no_mangle]
pub extern "C" fn Java_dawn_android_LibraryConnector_initCrypto<'local> (
	env: JNIEnv<'local>,
	_class: JClass<'local>,
) -> JString<'local> {
	
	let ((own_pubkey_kyber, own_seckey_kyber), (own_pubkey_curve, own_seckey_curve), id) = init_crypto();
	let init_crypto = InitCrypto {
		status: "ok",
		id: &id,
		own_pubkey_kyber: &encode(own_pubkey_kyber),
		own_seckey_kyber: &encode(own_seckey_kyber),
		own_pubkey_curve: &encode(own_pubkey_curve),
		own_seckey_curve: &encode(own_seckey_curve)
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
