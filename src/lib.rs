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

mod messaging;
mod macros;

use std::convert::TryFrom;
use dawn_stdlib::*;
use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::jshort;
use serde::{Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD as BASE64};

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


