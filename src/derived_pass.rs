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

use std::fmt::Display;

use anyhow::Result;

use crate::{
    DerivePassError,
    service_secret::ServiceSecret,
    user_input::{CharSet, PasswordLength},
};

pub struct DerivedPass {
    derived_pass: String,
}

impl DerivedPass {
    pub fn new(
        service_secret: &ServiceSecret,
        char_set: &CharSet,
        password_length: &PasswordLength,
    ) -> Result<DerivedPass> {
        if service_secret.len() < password_length.as_usize() {
            return Err(DerivePassError::Char.into());
        }
        let mut derived_pass: String = "".to_owned();
        for i in 0..password_length.as_u8() {
            let hash_byte: usize = service_secret
                .as_bytes()
                .get(usize::from(i))
                .ok_or(DerivePassError::Char)?
                .to_owned()
                .into();
            derived_pass.push(Self::get_password_char(char_set, hash_byte)?);
        }
        Ok(DerivedPass { derived_pass })
    }
    fn get_password_char(char_pool: &CharSet, secret_byte: usize) -> Result<char> {
        let char_pool_string = char_pool.to_string();
        Ok(char_pool
            .to_string()
            .chars()
            .nth(secret_byte % char_pool_string.len())
            .ok_or(DerivePassError::Char)?)
    }
}

impl Display for DerivedPass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.derived_pass)
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::utils::Utils;

    use super::*;

    #[test]
    fn can_small_letter_pool() {
        let expected_result = "abcdefghijklmnopqrstuvwxyza";
        let test_secret: Vec<u8> = Vec::from_iter(0..64);
        assert_eq!(
            DerivedPass::new(
                &ServiceSecret::from_str(&Utils::bytes_to_hex(&test_secret)).unwrap(),
                &CharSet::try_from([0].as_slice()).unwrap(),
                &PasswordLength::from_str("27").unwrap()
            )
            .unwrap()
            .to_string(),
            expected_result
        );
    }
    #[test]
    fn can_capital_letter_pool() {
        let expected_result = "ABCDEFGHIJKLMNOPQRSTUVWXYZA";
        let test_secret: Vec<u8> = Vec::from_iter(0..64);
        assert_eq!(
            DerivedPass::new(
                &ServiceSecret::from_str(&Utils::bytes_to_hex(&test_secret)).unwrap(),
                &CharSet::try_from([1].as_slice()).unwrap(),
                &PasswordLength::from_str("27").unwrap()
            )
            .unwrap()
            .to_string(),
            expected_result
        );
    }
    #[test]
    fn can_number_pool() {
        let expected_result = "01234567890";
        let test_secret: Vec<u8> = Vec::from_iter(0..64);

        assert_eq!(
            DerivedPass::new(
                &ServiceSecret::from_str(&Utils::bytes_to_hex(&test_secret)).unwrap(),
                &CharSet::try_from([2].as_slice()).unwrap(),
                &PasswordLength::from_str("11").unwrap()
            )
            .unwrap()
            .to_string(),
            expected_result
        );
    }
    #[test]
    fn can_special_chars_pool() {
        let expected_result = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~!"##;
        let test_secret: Vec<u8> = Vec::from_iter(0..64);
        assert_eq!(
            DerivedPass::new(
                &ServiceSecret::from_str(&Utils::bytes_to_hex(&test_secret)).unwrap(),
                &CharSet::try_from([3].as_slice()).unwrap(),
                &PasswordLength::from_str("33").unwrap()
            )
            .unwrap()
            .to_string(),
            expected_result
        );
    }
}
