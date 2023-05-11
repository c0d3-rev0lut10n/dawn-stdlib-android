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

mod crypto;
mod handles;
mod init;
mod macros;
mod messaging;

use serde::{Serialize};

#[derive(Serialize)]
struct Error<'a> {
	status: &'a str
}

// Used in the crypto module:

#[derive(Serialize)]
struct InitCrypto<'a> {
	status: &'a str,
	id: &'a str,
	own_pubkey_kyber: &'a str,
	own_seckey_kyber: &'a str,
	own_pubkey_curve: &'a str,
	own_seckey_curve: &'a str
}

#[derive(Serialize)]
struct SignKeys<'a> {
	status: &'a str,
	own_pubkey_sig: &'a str,
	own_seckey_sig: &'a str
}

#[derive(Serialize)]
struct SymKey<'a> {
	status: &'a str,
	key: &'a str
}

#[derive(Serialize)]
struct GenId<'a> {
	status: &'a str,
	id: &'a str
}

#[derive(Serialize)]
struct TempId<'a> {
	status: &'a str,
	id: &'a str
}

#[derive(Serialize)]
struct NextId<'a> {
	status: &'a str,
	id: &'a str
}

#[derive(Serialize)]
struct EncryptFile<'a> {
	status: &'a str,
	key: &'a str,
	ciphertext: &'a str
}

#[derive(Serialize)]
struct DecryptFile<'a> {
	status: &'a str,
	file: &'a str
}

// Used in the messaging module:

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

// Used in the handles module:

#[derive(Serialize)]
struct GenHandle<'a> {
	status: &'a str,
	handle: &'a str
}

#[derive(Serialize)]
struct ParseHandle<'a> {
	status: &'a str,
	init_pk_kyber: &'a str,
	init_pk_curve: &'a str,
	name: &'a str
}

// Used in the init module:

#[derive(Serialize)]
struct GenInitRequest<'a> {
	status: &'a str,
	own_pubkey_kyber: &'a str,
	own_seckey_kyber: &'a str,
	own_pubkey_curve: &'a str,
	own_seckey_curve: &'a str,
	pfs_key: &'a str,
	id: &'a str,
	mdc: &'a str,
	ciphertext: &'a str
}

#[derive(Serialize)]
struct ParseInitRequest<'a> {
	status: &'a str,
	id: &'a str,
	mdc: &'a str,
	remote_pubkey_kyber: &'a str,
	remote_pubkey_sig: &'a str,
	new_pfs_key: &'a str,
	name: &'a str,
	comment: &'a str
}

#[derive(Serialize)]
struct AcceptInitRequest<'a> {
	status: &'a str,
	new_pfs_key: &'a str,
	own_pubkey_kyber: &'a str,
	own_seckey_kyber: &'a str,
	mdc: &'a str,
	ciphertext: &'a str
}

#[derive(Serialize)]
struct ParseInitResponse<'a> {
	status: &'a str,
	remote_pubkey_kyber: &'a str,
	remote_pubkey_sig: &'a str,
	new_pfs_key: &'a str,
	mdc: &'a str
}
