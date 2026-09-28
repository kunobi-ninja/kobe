//! Apple Remote Desktop authentication (RFB security type 30).
//!
//! macOS Screen Sharing offers no unauthenticated security type. Type 30 is
//! the Diffie-Hellman scheme every VNC client that talks to a Mac implements:
//! the server sends a generator, a prime and its public key; both sides derive
//! a shared secret; its MD5 keys AES-128-ECB, which encrypts a fixed 128-byte
//! block holding the account name and password.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use anyhow::{Result, bail};
use md5::{Digest, Md5};
use num_bigint::BigUint;

/// The RFB security type number for this scheme.
pub(crate) const SECURITY_TYPE: u8 = 30;

/// Each credential field is 64 bytes: the UTF-8 text, a NUL, then filler.
const FIELD: usize = 64;

/// What the server sends after the client picks type 30.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Challenge {
    pub generator: u16,
    pub prime: Vec<u8>,
    pub server_key: Vec<u8>,
}

/// Lay out one credential field: text, NUL, then `filler` bytes. The filler
/// is random in a real session; the server stops reading at the NUL.
pub(crate) fn credential_field(text: &str, filler: &[u8; FIELD]) -> Result<[u8; FIELD]> {
    let bytes = text.as_bytes();
    if bytes.len() >= FIELD {
        bail!("Screen Sharing accepts at most {} bytes here", FIELD - 1);
    }
    if bytes.contains(&0) {
        bail!("a NUL byte cannot be sent in a Screen Sharing login");
    }
    let mut field = *filler;
    field[..bytes.len()].copy_from_slice(bytes);
    field[bytes.len()] = 0;
    Ok(field)
}

/// Big-endian `value`, left-padded with zeros to `length` bytes.
fn padded(value: &BigUint, length: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0u8; length.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

/// The client's reply: 128 encrypted credential bytes, then its public key
/// padded to the prime's length.
///
/// `private_key` and `filler` are the random inputs, passed in so a test can
/// replay a session. `private_key` must be as long as the prime.
pub(crate) fn response(
    challenge: &Challenge,
    user: &str,
    password: &str,
    private_key: &[u8],
    filler: &[u8; 2 * FIELD],
) -> Result<Vec<u8>> {
    let length = challenge.prime.len();
    if length == 0 || challenge.server_key.len() != length {
        bail!("malformed Screen Sharing key exchange");
    }
    let prime = BigUint::from_bytes_be(&challenge.prime);
    let generator = BigUint::from(challenge.generator);
    let private = BigUint::from_bytes_be(private_key);
    let public = generator.modpow(&private, &prime);
    let shared = BigUint::from_bytes_be(&challenge.server_key).modpow(&private, &prime);

    let key = Md5::digest(padded(&shared, length));
    let cipher = Aes128::new(&key);

    let mut block = [0u8; 2 * FIELD];
    let (user_filler, password_filler) = filler.split_at(FIELD);
    block[..FIELD].copy_from_slice(&credential_field(user, user_filler.try_into()?)?);
    block[FIELD..].copy_from_slice(&credential_field(password, password_filler.try_into()?)?);
    for chunk in block.chunks_exact_mut(16) {
        let chunk: &mut [u8; 16] = chunk.try_into().expect("16-byte chunks");
        cipher.encrypt_block(chunk.into());
    }

    let mut reply = block.to_vec();
    reply.extend_from_slice(&padded(&public, length));
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockDecrypt;

    /// A 128-bit prime is enough to exercise the arithmetic; Screen Sharing
    /// sends a much larger one.
    const PRIME: [u8; 16] = [
        0xd5, 0xbb, 0xb9, 0x6d, 0x30, 0x08, 0x6e, 0xc4, 0x84, 0xeb, 0xa3, 0xd7, 0xf9, 0xca, 0xeb,
        0x07,
    ];

    fn server_key(private: &[u8]) -> Vec<u8> {
        padded(
            &BigUint::from(2u32).modpow(
                &BigUint::from_bytes_be(private),
                &BigUint::from_bytes_be(&PRIME),
            ),
            PRIME.len(),
        )
    }

    /// Play the server: derive the shared secret from the client's public
    /// key and the server's own private key, the way a Mac does, and read the
    /// credentials back. Agreement here is what the real server checks.
    #[test]
    fn the_server_recovers_the_credentials() {
        let server_private = [7u8; 16];
        let challenge = Challenge {
            generator: 2,
            prime: PRIME.to_vec(),
            server_key: server_key(&server_private),
        };
        let reply = response(&challenge, "ci", "s3cret pass", &[9u8; 16], &[0xaa; 128]).unwrap();
        assert_eq!(reply.len(), 128 + PRIME.len());

        let (mut block, client_public) = (reply[..128].to_vec(), &reply[128..]);
        let shared = BigUint::from_bytes_be(client_public).modpow(
            &BigUint::from_bytes_be(&server_private),
            &BigUint::from_bytes_be(&PRIME),
        );
        let key = Md5::digest(padded(&shared, PRIME.len()));
        let cipher = Aes128::new(&key);
        for chunk in block.chunks_exact_mut(16) {
            let chunk: &mut [u8; 16] = chunk.try_into().unwrap();
            cipher.decrypt_block(chunk.into());
        }
        let text = |field: &[u8]| {
            let end = field.iter().position(|&b| b == 0).unwrap();
            String::from_utf8(field[..end].to_vec()).unwrap()
        };
        assert_eq!(text(&block[..64]), "ci");
        assert_eq!(text(&block[64..]), "s3cret pass");
    }

    #[test]
    fn a_field_is_text_then_nul_then_filler() {
        let field = credential_field("ab", &[0xee; 64]).unwrap();
        assert_eq!(&field[..3], b"ab\0");
        assert!(field[3..].iter().all(|&b| b == 0xee));
        assert!(credential_field(&"x".repeat(63), &[0; 64]).is_ok());
        assert!(credential_field(&"x".repeat(64), &[0; 64]).is_err());
        assert!(credential_field("a\0b", &[0; 64]).is_err());
    }

    #[test]
    fn keys_are_padded_to_the_prime_length() {
        assert_eq!(padded(&BigUint::from(1u32), 4), vec![0, 0, 0, 1]);
        let challenge = Challenge {
            generator: 2,
            prime: PRIME.to_vec(),
            server_key: vec![0; 15],
        };
        assert!(response(&challenge, "a", "b", &[1; 16], &[0; 128]).is_err());
    }
}
