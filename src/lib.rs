use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::ToRsaPublicKey, PaddingScheme, PublicKey};
use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use base64;
use once_cell::sync::Lazy;

// Static keys
static KEYS: Lazy<std::sync::Mutex<Option<(RsaPrivateKey, RsaPublicKey)>>> = Lazy::new(|| std::sync::Mutex::new(None));

#[wasm_bindgen]
pub fn generate_keys() -> String {
    let mut rng = OsRng;

    // Generate keys
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    // Store keys in static variable
    let mut keys_lock = KEYS.lock().unwrap();
    *keys_lock = Some((private_key, public_key.clone())); // Cloning the public key

    // Return the public key in base64-encoded DER format
    let public_key_der = public_key.to_pkcs1_der().expect("Failed to serialize public key");
    base64::encode(public_key_der)
}

#[wasm_bindgen]
pub fn encrypt_message(message: &str) -> String {
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();

    let keys_lock = KEYS.lock().unwrap();
    if let Some((_, public_key)) = &*keys_lock {
        let encrypted_data = public_key.encrypt(&mut rng, padding, message.as_bytes())
            .expect("Failed to encrypt message");
        return base64::encode(encrypted_data);
    }

    "Error: Public key not found".to_string()
}

#[wasm_bindgen]
pub fn decrypt_message(encrypted_message: &str) -> String {
    let padding = PaddingScheme::new_pkcs1v15_encrypt();

    let keys_lock = KEYS.lock().unwrap();
    if let Some((private_key, _)) = &*keys_lock {
        let encrypted_data = base64::decode(&encrypted_message).expect("Failed to decode base64");
        let decrypted_data = private_key.decrypt(padding, &encrypted_data)
            .expect("Failed to decrypt message");
        return String::from_utf8(decrypted_data).expect("Failed to convert decrypted data to string");
    }

    "Error: Private key not found".to_string()
}
