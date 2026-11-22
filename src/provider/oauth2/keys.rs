use super::*;
use crate::{models::ClientCryptographicKey, token::generate_token};
use rsa::{
    Generate, PrivateKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
    traits::PublicKeyParts,
};
use serde_json::Value;

fn crypto_error(error: impl std::fmt::Display) -> OAuthError {
    eprintln!("OAuth signing operation failed: {error}");
    OAuthError {
        status: StatusCode::INTERNAL_SERVER_ERROR,
        code: "server_error",
        description: "Unable to prepare signing credentials.".into(),
    }
}

static KEY_GENERATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn usable(
    db: &mut dyn toasty::Executor,
    client: &Client,
) -> Result<Option<ClientCryptographicKey>> {
    let now = jiff::Timestamp::now().as_second();
    let mut keys =
        ClientCryptographicKey::filter(ClientCryptographicKey::fields().client_id().eq(client.id))
            .exec(db)
            .await?;
    keys.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(keys
        .into_iter()
        .find(|k| k.expires_at.as_second() > now + ACCESS_LIFETIME + 60))
}

pub(crate) async fn ensure(
    db: &mut dyn toasty::Executor,
    client: &Client,
) -> Result<ClientCryptographicKey> {
    if let Some(key) = usable(db, client).await? {
        return Ok(key);
    }
    // Concurrent public JWKS requests should share the first generated key,
    // rather than each starting an expensive RSA generation job.
    let _generation = KEY_GENERATION.lock().await;
    if let Some(key) = usable(db, client).await? {
        return Ok(key);
    }
    let now = jiff::Timestamp::now().as_second();
    let material = tokio::task::spawn_blocking(|| -> anyhow::Result<Value> {
        let private = PrivateKey::try_generate()?;
        let public = private.to_public_key();
        let kid = generate_token();
        Ok(json!({
            "private_pkcs8": URL_SAFE_NO_PAD.encode(private.to_pkcs8_der()?.as_bytes()),
            "public": { "kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
                "n": URL_SAFE_NO_PAD.encode(public.n_bytes()), "e": URL_SAFE_NO_PAD.encode(public.e_bytes()) }
        }))
    }).await.map_err(crypto_error)?.map_err(crypto_error)?;
    let expires = jiff::Timestamp::from_second(now + 90 * 86400).map_err(crypto_error)?;
    Ok(toasty::create!(ClientCryptographicKey {
        client_id: client.id,
        key: toasty::Json(material),
        expires_at: expires
    })
    .exec(db)
    .await?)
}

pub(crate) async fn jwks(core: &Core, client: &Client) -> Result<Value> {
    let mut db = core.db.clone();
    ensure(&mut db, client).await?;
    let keys =
        ClientCryptographicKey::filter(ClientCryptographicKey::fields().client_id().eq(client.id))
            .exec(&mut db)
            .await?;
    let now = jiff::Timestamp::now();
    Ok(
        json!({ "keys": keys.into_iter().filter(|k| k.expires_at > now).filter_map(|k| k.key.0.get("public").cloned()).collect::<Vec<_>>() }),
    )
}

pub(crate) async fn sign(key: &ClientCryptographicKey, claims: Value) -> Result<String> {
    let material = key.key.0.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let encoded = material
            .get("private_pkcs8")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("Missing signing material"))?;
        let kid = material["public"]["kid"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing signing key id"))?;
        let key = PrivateKey::from_pkcs8_der(&URL_SAFE_NO_PAD.decode(encoded)?)?;
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(
            &json!({ "alg": "RS256", "typ": "JWT", "kid": kid }),
        )?);
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let message = format!("{header}.{payload}");
        let signature = key.pkcs1v15_sign::<rsa::sha2::Sha256>(message.as_bytes())?;
        Ok(format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature)))
    })
    .await
    .map_err(crypto_error)?
    .map_err(crypto_error)
}
