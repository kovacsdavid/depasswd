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

pub struct Utils {}

impl Utils {
    pub fn bytes_to_hex(b: &[u8]) -> String {
        b.iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("")
    }
    pub fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
        if s.len() % 2 == 0 {
            (0..s.len())
                .step_by(2)
                .map(|i| {
                    s.get(i..i + 2)
                        .and_then(|sub| u8::from_str_radix(sub, 16).ok())
                })
                .collect()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn can_bytes_to_hex() {
        let test_bytes: [u8; 10] = [0, 0, 0, 0, 0, 255, 255, 255, 255, 255];
        let test_hex = "0000000000ffffffffff";

        assert_eq!(Utils::bytes_to_hex(&test_bytes), test_hex);
    }

    #[test]
    pub fn can_bytes_to_hex_2() {
        let test_bytes = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"##.as_bytes();
        let test_hex = "2122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5d5e5f607b7c7d7e6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a";

        assert_eq!(Utils::bytes_to_hex(&test_bytes), test_hex);
    }

    #[test]
    pub fn can_hex_to_bytes() {
        let test_bytes: [u8; 10] = [0, 0, 0, 0, 0, 255, 255, 255, 255, 255];
        let test_hex = "0000000000ffffffffff";

        assert_eq!(Utils::hex_to_bytes(test_hex).unwrap(), test_bytes);
    }

    #[test]
    pub fn can_hex_to_bytes_2() {
        let test_bytes = r##"!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"##.as_bytes();
        let test_hex = "2122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5d5e5f607b7c7d7e6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435363738394142434445464748494a4b4c4d4e4f505152535455565758595a";

        assert_eq!(Utils::hex_to_bytes(&test_hex).unwrap(), test_bytes);
    }
}
