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

use depasswd::{
    DerivePassRunner, UserInputProvider,
    user_input::{CharSet, Generation, MasterPasswordPlain, PasswordLength, ServiceID, UserID},
};

struct TestUserInput {
    user_id: UserID,
    master_password_plain: MasterPasswordPlain,
    service_id: ServiceID,
    generation: Generation,
    char_set: CharSet,
    password_length: PasswordLength,
}

impl TestUserInput {
    fn new(
        user_id: UserID,
        master_password_plain: MasterPasswordPlain,
        service_id: ServiceID,
        generation: Generation,
        char_set: CharSet,
        password_length: PasswordLength,
    ) -> Self {
        Self {
            user_id,
            master_password_plain,
            service_id,
            generation,
            char_set,
            password_length,
        }
    }
}

impl UserInputProvider for TestUserInput {
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
        &self.char_set
    }
    fn get_password_length(&self) -> &PasswordLength {
        &self.password_length
    }
}

#[test]
fn integration_test1() {
    let test_user_input_1 = TestUserInput::new(
        UserID::from_str("Example Eleonora").unwrap(),
        MasterPasswordPlain::from_str(r##"]lE~WExZ468ty{I5mtg["##).unwrap(),
        ServiceID::from_str("Example Service Name").unwrap(),
        Generation::from_str("1").unwrap(),
        CharSet::try_from([0, 1, 2, 3].as_slice()).unwrap(),
        PasswordLength::from_str("20").unwrap(),
    );
    let test_user_input_2 = TestUserInput::new(
        UserID::from_str(r##"]lE~WExZ468ty{I5mtg["##).unwrap(),
        MasterPasswordPlain::from_str(r##"e~z[Ced10sDY|VRA24Q3j)7.B.mvu4;QFo=&7@-D"##).unwrap(),
        ServiceID::from_str(r##"+b8R~?gV2|+0gtQ<QEv<"##).unwrap(),
        Generation::from_str("100").unwrap(),
        CharSet::try_from([0, 1, 2, 3].as_slice()).unwrap(),
        PasswordLength::from_str("64").unwrap(),
    );

    assert_eq!(
        "1@MWtAAqZ0p>;;y@zZ6d",
        DerivePassRunner::run(&test_user_input_1)
            .unwrap()
            .to_string()
    );
    assert_eq!(
        "1@MWtAAqZ0p>;;y@zZ6d",
        DerivePassRunner::run(&test_user_input_1)
            .unwrap()
            .to_string()
    );
    assert_eq!(
        r##"7o^qjF"dFpX;sp,8bwE#+c&FRIDUfM`o,1e}Q2K{+mc%I:~vVd2u$V&=_<\n{M--"##,
        DerivePassRunner::run(&test_user_input_2)
            .unwrap()
            .to_string()
    );
    assert_eq!(
        r##"7o^qjF"dFpX;sp,8bwE#+c&FRIDUfM`o,1e}Q2K{+mc%I:~vVd2u$V&=_<\n{M--"##,
        DerivePassRunner::run(&test_user_input_2)
            .unwrap()
            .to_string()
    );
}
