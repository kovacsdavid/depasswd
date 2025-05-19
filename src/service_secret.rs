/*
 * This file is part of depasswd stateless password manager.
 *
 * Copyright (C) 2025 Kovács Dávid <kapcsolat@kovacsdavid.dev>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::str::FromStr;

use anyhow::Result;
use base64::prelude::*;
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::{
    DerivePassError,
    master_secret::MasterSecret,
    user_input::{Generation, PasswordLength, ServiceID},
    utils::Utils,
};

type HmacSha512 = Hmac<Sha512>;

pub struct ServiceSecret {
    service_secret: Vec<u8>,
}

impl ServiceSecret {
    pub fn new(
        master_secret: &MasterSecret,
        service_id: &ServiceID,
        generation: &Generation,
        password_length: &PasswordLength,
    ) -> Result<ServiceSecret> {
        let salt = BASE64_STANDARD_NO_PAD.encode(
            service_id.len().to_string()
                + &service_id.to_string()
                + &password_length.to_string()
                + &generation.to_string(),
        );

        let mut hmac_sha512 = HmacSha512::new_from_slice(master_secret.as_hex().as_bytes())?;
        hmac_sha512.update(&salt.as_bytes());

        Ok(ServiceSecret {
            service_secret: hmac_sha512.finalize().into_bytes().to_vec(),
        })
    }
    pub fn len(&self) -> usize {
        self.service_secret.len()
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.service_secret
    }
}

impl FromStr for ServiceSecret {
    type Err = DerivePassError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() == 128 {
            Ok(Self {
                service_secret: Utils::hex_to_bytes(s).ok_or(DerivePassError::Secret)?,
            })
        } else {
            Err(DerivePassError::Secret)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::utils::Utils;

    use super::*;

    #[test]
    fn can_generate_valid_service_secret() {
        let test_cases = vec![
            vec![
                r##"4x9*1V{5lh"##,
                "7ad5d8df9f80f749fd4316c9681719eb7ba29c24c38311d0e9bb56047024ab91",
                "1",
                "10",
                "615af93471fc2c9356c4c99d41a1f9af3ae0f01fc7f41e62e9054e51faf9b34979383ed5d9193f3d6f6647d2274d80655fb2533fb91af2a64cc6912fb3724e90",
            ],
            vec![
                r##"K0d21[-=%Req6iLf;:?L"##,
                "c2032d81f69aafdf9de7a5200a5b157f80363a621dee591f83bf7b0a3a8955af",
                "2",
                "20",
                "36f3d927cd6f741f3dc7b17a07dc292773674e3551cca3a3425bdef06975786c04d6c69b879290896a86ddb6dece0f5afeea513d99b8185866bcf791796c453d",
            ],
            vec![
                r##"u"D2YT2f5WB#fDJ>j3e~s,V''HW?:("##,
                "f2c9c06c48f9f88b5a47b3e26f1827333506341dd469f475ebd5c62e68c14031",
                "3",
                "30",
                "d95650e726a4596dfd42d0df5b0f9f25f6d491313aec61bf7c8d120b4b71743b93ec89fe28837473b43331c30e18e30b6a4d7f80ca63423fda7403b145207ae4",
            ],
            vec![
                r##"Tre6-:52:QMM97=,)[ZZ_f{%QH`L>?eu.{B"(AhT"##,
                "e989ce35945abae888eca249b1bf8a4098ddfe3699c462daafcf645f01c7089c",
                "4",
                "40",
                "060fa7449f7d9352ac9257a61f351c9cea4338405a5ca58051fbd35de2ee1997720b5268ae35b03ce529cbe29eb3fbdbd5c1a3ae4b6f15631f72b467159e4238",
            ],
        ];

        for test_case in test_cases.iter() {
            assert_eq!(
                ServiceSecret::new(
                    &MasterSecret::from_str(test_case.get(1).unwrap()).unwrap(),
                    &ServiceID::from_str(test_case.get(0).unwrap()).unwrap(),
                    &Generation::from_str(test_case.get(2).unwrap()).unwrap(),
                    &PasswordLength::from_str(test_case.get(3).unwrap()).unwrap()
                )
                .unwrap()
                .as_bytes(),
                Utils::hex_to_bytes(test_case.get(4).unwrap()).unwrap()
            );
        }
    }
}
