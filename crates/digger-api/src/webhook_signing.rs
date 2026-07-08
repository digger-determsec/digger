/// Webhook HMAC signature utilities — sign payloads and verify deliveries.
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign a payload with HMAC-SHA256 using the webhook secret.
pub fn sign_payload(secret: &str, payload: &str) -> String {
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => unreachable!("HMAC accepts keys of any size"),
    };
    mac.update(payload.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Verify an HMAC-SHA256 signature against a payload.
pub fn verify_signature(secret: &str, payload: &str, signature: &str) -> bool {
    let expected = sign_payload(secret, payload);
    // Constant-time comparison
    expected.len() == signature.len()
        && expected
            .bytes()
            .zip(signature.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let secret = "test-secret-key";
        let payload = r#"{"event":"scan.completed","data":{}}"#;
        let sig = sign_payload(secret, payload);
        assert!(verify_signature(secret, payload, &sig));
        assert!(!verify_signature("wrong-key", payload, &sig));
        assert!(!verify_signature(secret, "wrong-payload", &sig));
    }
}
