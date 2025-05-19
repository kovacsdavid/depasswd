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
use argon2::{
    Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use base64::prelude::*;

use crate::{
    DerivePassError,
    user_input::{MasterPasswordPlain, UserID},
    utils::Utils,
};

pub struct MasterSecret {
    master_secret: Vec<u8>,
}

impl MasterSecret {
    pub fn new(
        user_id: &UserID,
        master_password_plain: &MasterPasswordPlain,
    ) -> Result<MasterSecret> {
        let salt = BASE64_STANDARD_NO_PAD.encode(user_id.len().to_string() + &user_id.to_string());
        let salt_string = SaltString::from_b64(&salt)?;

        Ok(MasterSecret {
            master_secret: Argon2::new(
                argon2::Algorithm::Argon2id,
                Version::V0x13,
                Params::new(32 * 1024, 4, 4, None)?,
            )
            .hash_password(&master_password_plain.as_bytes(), &salt_string)?
            .hash
            .ok_or(DerivePassError::Secret)?
            .as_bytes()
            .to_owned(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.master_secret
    }
    pub fn as_hex(&self) -> String {
        Utils::bytes_to_hex(&self.master_secret)
    }
}

impl FromStr for MasterSecret {
    type Err = DerivePassError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() == 64 {
            Ok(Self {
                master_secret: Utils::hex_to_bytes(s).ok_or(DerivePassError::Secret)?,
            })
        } else {
            Err(DerivePassError::Secret)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use argon2::PasswordHash;

    #[test]
    fn can_generate_valid_master_secret() {
        let test_cases = vec![
            vec![
                r##"4x9*1V{5lh"##,
                r##"<J91=0iC3`"##,
                "$argon2id$v=19$m=32768,t=4,p=4$MTA0eDkqMVZ7NWxo$etXY35+A90n9QxbJaBcZ63uinCTDgxHQ6btWBHAkq5E",
            ],
            vec![
                r##"K0d21[-=%Req6iLf;:?L"##,
                r##"7s4$tN9sHmoa\|tTp)RS"##,
                "$argon2id$v=19$m=32768,t=4,p=4$MjBLMGQyMVstPSVSZXE2aUxmOzo/TA$wgMtgfaar9+d56UgClsVf4A2OmId7lkfg797CjqJVa8",
            ],
            vec![
                r##"u"D2YT2f5WB#fDJ>j3e~s,V''HW?:("##,
                r##"54VZ£1<QU9#jpDZ2u/$6FjXjG8n;N-"##,
                "$argon2id$v=19$m=32768,t=4,p=4$MzB1IkQyWVQyZjVXQiNmREo+ajNlfnMsVicnSFc/Oig$8snAbEj5+ItaR7PibxgnMzUGNB3UafR169XGLmjBQDE",
            ],
            vec![
                r##"Tre6-:52:QMM97=,)[ZZ_f{%QH`L>?eu.{B"(AhT"##,
                r##"9+NO9&VFdqTK8dP;egNOuBbe985*(!P=2QC1,O>F"##,
                "$argon2id$v=19$m=32768,t=4,p=4$NDBUcmU2LTo1MjpRTU05Nz0sKVtaWl9meyVRSGBMPj9ldS57QiIoQWhU$6YnONZRauuiI7KJJsb+KQJjd/jaZxGLar89kXwHHCJw",
            ],
        ];

        for test_case in test_cases {
            assert_eq!(
                MasterSecret::new(
                    &UserID::from_str(*test_case.get(0).unwrap()).unwrap(),
                    &MasterPasswordPlain::from_str(test_case.get(1).unwrap()).unwrap()
                )
                .unwrap()
                .as_bytes(),
                PasswordHash::new(test_case.get(2).unwrap())
                    .unwrap()
                    .hash
                    .unwrap()
                    .as_bytes()
            );
        }
    }
}
