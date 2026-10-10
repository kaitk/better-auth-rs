use super::*;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};

pub(super) fn hash_otp(code: &str) -> AuthResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(code.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| AuthError::PasswordHash(format!("Failed to hash OTP: {error}")))
}

pub(super) fn verify_otp(code: &str, hash: &str) -> AuthResult<bool> {
    let hash = PasswordHash::new(hash)
        .map_err(|error| AuthError::PasswordHash(format!("Invalid OTP hash: {error}")))?;
    Ok(Argon2::default()
        .verify_password(code.as_bytes(), &hash)
        .is_ok())
}

pub(super) fn build_totp(
    config: &TwoFactorConfig,
    secret: &str,
    request_issuer: Option<&str>,
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<TOTP> {
    let issuer = request_issuer
        .map(str::to_owned)
        .or_else(|| config.issuer.clone())
        .unwrap_or_else(|| ctx.config.app_name.clone());
    let account_name = user.email().unwrap_or("user").to_string();
    TOTP::new(
        Algorithm::SHA1,
        config.totp_digits,
        1,
        config.totp_period,
        secret.as_bytes().to_vec(),
        Some(issuer),
        account_name,
    )
    .map_err(|error| AuthError::internal(format!("Failed to create TOTP: {}", error)))
}

pub(super) async fn verify_user_password(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
    user: &impl AuthUser,
    password: &str,
) -> AuthResult<()> {
    let stored_hash = get_credential_password_hash(ctx, user)
        .await?
        .ok_or_else(|| AuthError::bad_request("Invalid password"))?;
    match better_auth_core::verify_password(None, password, &stored_hash).await {
        Ok(()) => Ok(()),
        Err(AuthError::InvalidCredentials) => Err(AuthError::bad_request("Invalid password")),
        Err(error) => Err(error),
    }
}

pub(super) fn generate_secret() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub(super) fn generate_backup_codes() -> Vec<String> {
    (0..DEFAULT_BACKUP_CODE_COUNT)
        .map(|_| {
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(DEFAULT_BACKUP_CODE_LENGTH)
                .map(char::from)
                .collect::<String>()
        })
        .map(|code| format!("{}-{}", &code[..5], &code[5..]))
        .collect()
}

pub(super) fn decrypt_backup_codes(
    backup_codes: &str,
    secret: &str,
) -> AuthResult<Option<Vec<String>>> {
    let decrypted = decrypt_value(secret, backup_codes)?;
    serde_json::from_str(&decrypted)
        .ok()
        .map_or(Ok(None), |codes| Ok(Some(codes)))
}

pub(super) fn otp_verification_identifier(key: &str) -> String {
    format!("2fa-otp-{}", key)
}

pub(super) fn two_factor_cookie_max_age(
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> i64 {
    ctx.get_metadata(METADATA_TWO_FACTOR_COOKIE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TWO_FACTOR_COOKIE_MAX_AGE_SECS)
}

pub(super) fn trust_device_max_age(ctx: &AuthContext<impl better_auth_core::AuthSchema>) -> i64 {
    ctx.get_metadata(METADATA_TRUST_DEVICE_MAX_AGE)
        .and_then(|value| value.as_i64())
        .unwrap_or(DEFAULT_TRUST_DEVICE_MAX_AGE_SECS)
}

pub(super) fn create_session_cookie_for_dont_remember(
    token: &str,
    dont_remember: bool,
    config: &better_auth_core::AuthConfig,
) -> String {
    if dont_remember {
        create_session_cookie_with_max_age(Some(token), None, config)
    } else {
        create_session_cookie(token, config)
    }
}

pub(super) fn clear_cookie_header(config: &better_auth_core::AuthConfig, suffix: &str) -> String {
    create_clear_cookie(&related_cookie_name(config, suffix), config)
}

pub(super) async fn create_trust_device_cookie_header(
    user: &impl AuthUser,
    ctx: &AuthContext<impl better_auth_core::AuthSchema>,
) -> AuthResult<String> {
    let identifier = format!("trust-device-{}", uuid::Uuid::new_v4());
    let token = sign_value(&ctx.config.secret, &format!("{}!{}", user.id(), identifier))?;
    let value = format!("{}!{}", token, identifier);
    let expires_at = better_auth_core::time::now() + Duration::seconds(trust_device_max_age(ctx));
    _ = ctx
        .database
        .create_verification(CreateVerification {
            identifier: identifier.clone(),
            value: user.id().to_string(),
            expires_at,
        })
        .await?;
    create_signed_cookie_header(
        &ctx.config.secret,
        &ctx.config,
        TRUST_DEVICE_COOKIE_SUFFIX,
        &value,
        Some(trust_device_max_age(ctx)),
    )
}

pub(super) fn create_signed_cookie_header(
    secret: &str,
    config: &better_auth_core::AuthConfig,
    suffix: &str,
    value: &str,
    max_age_seconds: Option<i64>,
) -> AuthResult<String> {
    let cookie_name = related_cookie_name(config, suffix);
    let signed_value = sign_cookie_value(secret, value)?;
    Ok(create_session_like_cookie(
        &cookie_name,
        &signed_value,
        max_age_seconds,
        config,
    ))
}

pub(super) fn read_signed_cookie<S: better_auth_core::AuthSchema>(
    req: &AuthRequest,
    suffix: &str,
    ctx: &AuthContext<S>,
) -> AuthResult<Option<String>> {
    let cookie_name = related_cookie_name(&ctx.config, suffix);
    let Some(raw_cookie) = get_cookie(req, &cookie_name) else {
        return Ok(None);
    };
    verify_signed_cookie_value(&ctx.config.secret, &raw_cookie)
}

pub(super) fn sign_cookie_value(secret: &str, value: &str) -> AuthResult<String> {
    Ok(format!("{}.{}", value, sign_value(secret, value)?))
}

pub(super) fn verify_signed_cookie_value(
    secret: &str,
    signed_value: &str,
) -> AuthResult<Option<String>> {
    let Some((value, signature)) = signed_value.rsplit_once('.') else {
        return Ok(None);
    };
    Ok(verify_signature(secret, value, signature)?.then(|| value.to_string()))
}

pub(super) fn sign_value(secret: &str, value: &str) -> AuthResult<String> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

pub(super) fn verify_signature(secret: &str, value: &str, signature: &str) -> AuthResult<bool> {
    let decoded = match URL_SAFE_NO_PAD.decode(signature) {
        Ok(decoded) => decoded,
        Err(_) => return Ok(false),
    };
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret.as_bytes())
        .map_err(|error| AuthError::internal(format!("Failed to initialize HMAC: {}", error)))?;
    mac.update(value.as_bytes());
    Ok(mac.verify_slice(&decoded).is_ok())
}

pub(super) fn derive_encryption_key(secret: &str) -> AuthResult<Key<Aes256Gcm>> {
    let hkdf = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hkdf.expand(ENCRYPTION_INFO, &mut okm).map_err(|error| {
        AuthError::internal(format!("Failed to derive encryption key: {}", error))
    })?;
    Ok(okm.into())
}

pub(super) fn encrypt_value(secret: &str, plaintext: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|error| {
            AuthError::internal(format!("Failed to encrypt two-factor data: {}", error))
        })?;
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(output))
}

pub(super) fn decrypt_value(secret: &str, encrypted: &str) -> AuthResult<String> {
    let cipher = Aes256Gcm::new(&derive_encryption_key(secret)?);
    let bytes = URL_SAFE_NO_PAD.decode(encrypted).map_err(|error| {
        AuthError::internal(format!(
            "Failed to decode encrypted two-factor data: {}",
            error
        ))
    })?;
    let Some((nonce_bytes, ciphertext)) = bytes.split_first_chunk::<12>() else {
        return Err(AuthError::internal(
            "Encrypted two-factor payload is missing the nonce",
        ));
    };
    let nonce = Nonce::from(*nonce_bytes);
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|error| {
        AuthError::internal(format!("Failed to decrypt two-factor data: {}", error))
    })?;
    String::from_utf8(plaintext).map_err(|error| {
        AuthError::internal(format!(
            "Two-factor plaintext is not valid UTF-8: {}",
            error
        ))
    })
}
