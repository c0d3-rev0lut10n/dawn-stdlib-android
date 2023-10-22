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

#[macro_export]
macro_rules! error {
	($env: expr, $a: expr) => {
		let error = Error { status: &(String::from("@dawn-stdlib-android: ") + $a) };
		return $env.new_string(serde_json::to_string(&error).expect("Could not return error")).expect("Could not create new java string");
	}
}
