use rsa::{RsaPrivateKey, RsaPublicKey, pkcs1::ToRsaPublicKey, PaddingScheme, PublicKey};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use rand::rngs::OsRng;
use base64;
use once_cell::sync::Lazy;

// Static keys
static KEYS: Lazy<std::sync::Mutex<Option<(RsaPrivateKey, RsaPublicKey)>>> = Lazy::new(|| std::sync::Mutex::new(None));

// Function to generate keys for JNI
#[no_mangle]
pub extern "system" fn Java_net_vaha_rustwasmencryption_MainActivity_generate_1keys(
    env: JNIEnv,
    _: JClass,
) {
    let mut rng = OsRng;

    // Generate keys
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate private key");
    let public_key = RsaPublicKey::from(&private_key);

    // Store keys in static variable
    let mut keys_lock = KEYS.lock().unwrap();
    *keys_lock = Some((private_key, public_key.clone())); // Cloning the public key

    // Store public key in a variable to return it
    let public_key_der = public_key.to_pkcs1_der().expect("Failed to serialize public key");
    let public_key_base64 = base64::encode(public_key_der);

    // Pass the public key back to Kotlin
    let output = env.new_string(public_key_base64).expect("Couldn't create Java string!");
    let _ = output.into_inner(); // Use it later in your Kotlin code
}

// Function to encrypt a message for JNI
#[no_mangle]
pub extern "system" fn Java_net_vaha_rustwasmencryption_MainActivity_encrypt_1message(
    env: JNIEnv,
    _: JClass,
    message: JString,
) -> jstring {
    let message: String = env.get_string(message).expect("Couldn't get Java string!").into();
    let mut rng = OsRng;
    let padding = PaddingScheme::new_pkcs1v15_encrypt();

    let keys_lock = KEYS.lock().unwrap();
    if let Some((_, public_key)) = &*keys_lock {
        let encrypted_data = public_key.encrypt(&mut rng, padding, message.as_bytes())
            .expect("Failed to encrypt message");
        let encoded_data = base64::encode(encrypted_data);
        return env.new_string(encoded_data).expect("Couldn't create Java string!").into_inner();
    }

    env.new_string("Error: Public key not found").expect("Couldn't create Java string!").into_inner()
}

// Function to decrypt a message for JNI
#[no_mangle]
pub extern "system" fn Java_net_vaha_rustwasmencryption_MainActivity_decrypt_1message(
    env: JNIEnv,
    _: JClass,
    encrypted_message: JString,
) -> jstring {
    let encrypted_message: String = env.get_string(encrypted_message).expect("Couldn't get Java string!").into();
    let padding = PaddingScheme::new_pkcs1v15_encrypt();

    let keys_lock = KEYS.lock().unwrap();
    if let Some((private_key, _)) = &*keys_lock {
        let encrypted_data = base64::decode(&encrypted_message).expect("Failed to decode base64");
        let decrypted_data = private_key.decrypt(padding, &encrypted_data)
            .expect("Failed to decrypt message");
        return env.new_string(String::from_utf8(decrypted_data).expect("Failed to convert decrypted data to string")).expect("Couldn't create Java string!").into_inner();
    }

    env.new_string("Error: Private key not found").expect("Couldn't create Java string!").into_inner()
}
