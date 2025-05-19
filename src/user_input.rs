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

use std::{collections::HashMap, fmt::Display, str::FromStr};

use anyhow::Result;
use dialoguer::{Input, MultiSelect, Password, theme::ColorfulTheme};
use thiserror::Error;

use crate::{CAPITAL_LETTERS, NUMBERS, SMALL_LETTERS, SPECIAL_CHARS};

pub trait UserInputProvider {
    fn get_user_id(&self) -> &UserID;
    fn get_master_password_plain(&self) -> &MasterPasswordPlain;
    fn get_service_id(&self) -> &ServiceID;
    fn get_generation(&self) -> &Generation;
    fn get_char_set(&self) -> &CharSet;
    fn get_password_length(&self) -> &PasswordLength;
}

#[derive(Error, Debug)]
pub struct UserInputError(String);

impl Display for UserInputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "UserInputError: {}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct UserID {
    user_id: String,
}

impl UserID {
    pub fn len(&self) -> usize {
        self.user_id.len()
    }
}

impl FromStr for UserID {
    type Err = UserInputError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() >= 8 {
            Ok(Self {
                user_id: s.to_owned(),
            })
        } else {
            Err(UserInputError(
                "User ID length must be at least 8 character".to_owned(),
            ))
        }
    }
}

impl Display for UserID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_id)
    }
}

#[derive(Debug, Clone)]
pub struct MasterPasswordPlain {
    master_password_plain: String,
}

impl MasterPasswordPlain {
    pub fn as_bytes(&self) -> &[u8] {
        self.master_password_plain.as_bytes()
    }
}

impl FromStr for MasterPasswordPlain {
    type Err = UserInputError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if s.len() >= 8 {
            Ok(Self {
                master_password_plain: s.to_owned(),
            })
        } else {
            Err(UserInputError(
                "Master Password length must be at least 8 character".to_owned(),
            ))
        }
    }
}

impl Display for MasterPasswordPlain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.master_password_plain)
    }
}

#[derive(Debug, Clone)]
pub struct ServiceID {
    service_id: String,
}

impl ServiceID {
    pub fn len(&self) -> usize {
        self.service_id.len()
    }
}

impl FromStr for ServiceID {
    type Err = UserInputError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self {
            service_id: s.to_owned(),
        })
    }
}

impl Display for ServiceID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.service_id)
    }
}
#[derive(Debug, Clone)]
pub struct Generation {
    generation: usize,
}

impl Generation {
    pub fn as_usize(&self) -> usize {
        self.generation
    }
}

impl FromStr for Generation {
    type Err = UserInputError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.parse::<usize>() {
            Ok(value) => {
                if value > 0 {
                    Ok(Self { generation: value })
                } else {
                    Err(UserInputError(
                        "Generation must be a number greater than 0".to_owned(),
                    ))
                }
            }
            Err(_) => Err(UserInputError(
                "Generation must be a number greater than 0".to_owned(),
            )),
        }
    }
}

impl Display for Generation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.generation)
    }
}
#[derive(Debug, Clone)]
pub struct CharSet {
    char_set: String,
}

impl TryFrom<&[usize]> for CharSet {
    type Error = UserInputError;
    fn try_from(value: &[usize]) -> std::result::Result<Self, Self::Error> {
        let mut char_set = "".to_owned();
        let mut presets = HashMap::new();
        presets.insert(0, SMALL_LETTERS.to_owned());
        presets.insert(1, CAPITAL_LETTERS.to_owned());
        presets.insert(2, NUMBERS.to_owned());
        presets.insert(3, SPECIAL_CHARS.to_owned());

        for v in value {
            char_set += presets
                .get(v)
                .ok_or(UserInputError("Invalid character set!".to_owned()))?;
        }

        if char_set.is_empty() {
            return Err(UserInputError(
                "You must select at least one character set!".to_owned(),
            ));
        }

        Ok(Self { char_set })
    }
}

impl Display for CharSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.char_set)
    }
}
#[derive(Debug, Clone)]
pub struct PasswordLength {
    password_length: u8,
}

impl PasswordLength {
    pub fn as_u8(&self) -> u8 {
        self.password_length
    }
    pub fn as_usize(&self) -> usize {
        usize::from(self.password_length)
    }
}

impl FromStr for PasswordLength {
    type Err = UserInputError;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.parse::<u8>() {
            Ok(value) => {
                if value > 0 && value <= 64 {
                    Ok(Self {
                        password_length: value,
                    })
                } else {
                    Err(UserInputError(
                        "PasswordLength must be a number between 1 and 64".to_owned(),
                    ))
                }
            }
            Err(_) => Err(UserInputError(
                "PasswordLength must be a number between 1 and 64".to_owned(),
            )),
        }
    }
}

impl Display for PasswordLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.password_length)
    }
}

pub struct UserInputCli {
    user_id: UserID,
    master_password_plain: MasterPasswordPlain,
    service_id: ServiceID,
    generation: Generation,
    char_pools: CharSet,
    password_length: PasswordLength,
}

impl UserInputCli {
    pub fn new() -> Result<Self> {
        let user_id = Input::<UserID>::new()
            .with_prompt("User identifier (ex.: fullname, username...)")
            .interact_text()?;
        let service_id = Input::<ServiceID>::new()
            .with_prompt("Service identifier (ex.: name, url...)")
            .interact_text()?;
        let generation = Input::<Generation>::new()
            .with_prompt("Generation (increase this variable to regenerate password for a service) (default: 1)")
            .default(Generation::from_str("1")?)
            .interact_text()?;

        let char_pool_item = vec![
            "small letters [a-z]",
            "capital letters [A-Z]",
            "numbers [0-9]",
            r##"special characters [ !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ ]"##,
        ];
        let char_pool_item_defaults = vec![true, true, true, true];
        let mut char_pools = MultiSelect::new()
            .with_prompt("Choose character sets")
            .items(&char_pool_item)
            .defaults(&char_pool_item_defaults)
            .interact()?;

        while char_pools.is_empty() {
            char_pools = MultiSelect::new()
                .with_prompt("Choose at least one character set")
                .items(&char_pool_item)
                .interact()?;
        }

        let char_pools = CharSet::try_from(char_pools.as_slice())?;

        let password_length = Input::<PasswordLength>::new()
            .with_prompt("Password length (max 64)")
            .interact_text()?;

        let master_password_plain = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Master password")
            .interact()?;

        let master_password_plain = MasterPasswordPlain::from_str(&master_password_plain)?;

        Ok(Self {
            user_id,
            master_password_plain,
            service_id,
            generation,
            char_pools,
            password_length,
        })
    }
}

impl UserInputProvider for UserInputCli {
    fn get_user_id(&self) -> &UserID {
        &self.user_id
    }
    fn get_master_password_plain(&self) -> &MasterPasswordPlain {
        &self.master_password_plain
    }
    fn get_service_id(&self) -> &ServiceID {
        &self.service_id
    }
    fn get_generation(&self) -> &Generation {
        &self.generation
    }
    fn get_char_set(&self) -> &CharSet {
        &self.char_pools
    }
    fn get_password_length(&self) -> &PasswordLength {
        &self.password_length
    }
}
