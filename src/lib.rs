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

#![doc = include_str!("docs/lib.md")]

use anyhow::Result;
use derived_pass::DerivedPass;
use master_secret::MasterSecret;
use service_secret::ServiceSecret;
use thiserror::Error;
pub use user_input::UserInputProvider;

pub mod derived_pass;
pub mod master_secret;
pub mod service_secret;
pub mod user_input;
pub mod utils;

pub const SPECIAL_CHARS: &str = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"##;
pub const SMALL_LETTERS: &str = "abcdefghijklmnopqrstuvwxyz";
pub const NUMBERS: &str = "0123456789";
pub const CAPITAL_LETTERS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub struct DerivePassRunner {}

impl DerivePassRunner {
    pub fn run(user_input: &impl UserInputProvider) -> Result<DerivedPass> {
        Ok(DerivedPass::new(
            &ServiceSecret::new(
                &MasterSecret::new(
                    user_input.get_user_id(),
                    user_input.get_master_password_plain(),
                )?,
                user_input.get_service_id(),
                user_input.get_generation(),
                user_input.get_password_length(),
            )?,
            user_input.get_char_set(),
            user_input.get_password_length(),
        )?)
    }
}

#[derive(Error, Debug)]
pub enum DerivePassError {
    #[error("Secret error")]
    Secret,
    #[error("Character error")]
    Char,
}
