use rand;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

pub fn generate_token() -> String {
	let token = rand::random::<[u8; 32]>();
	URL_SAFE_NO_PAD.encode(&token)
}