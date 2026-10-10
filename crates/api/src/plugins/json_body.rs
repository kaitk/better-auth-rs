use better_auth_core::{AuthRequest, AuthResponse};
use serde_json::Value;

/// Parse the HTTP JSON boundary before endpoint schema validation.
pub(crate) fn parse(req: &AuthRequest) -> Result<Option<Value>, AuthResponse> {
    let Some(bytes) = req.body.as_deref().filter(|bytes| !bytes.is_empty()) else {
        return Ok(None);
    };
    let content_type = req
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .contains("application/json")
    {
        let message = if content_type.is_empty() {
            "Content-Type is required. Allowed types: application/json".to_owned()
        } else {
            format!(
                "Content-Type \"{content_type}\" is not allowed. Allowed types: application/json"
            )
        };
        return Err(error_response(415, "UNSUPPORTED_MEDIA_TYPE", &message));
    }
    serde_json::from_slice(bytes)
        .map(Some)
        .map_err(|_| error_response(400, "BAD_REQUEST", "Invalid JSON in request body"))
}

pub(crate) fn type_name(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

pub(crate) fn invalid_type(location: &str, expected: &str, value: Option<&Value>) -> String {
    format!(
        "[{location}] Invalid input: expected {expected}, received {}",
        type_name(value)
    )
}

pub(crate) fn validation_error(message: &str) -> AuthResponse {
    error_response(400, "VALIDATION_ERROR", message)
}

fn error_response(status: u16, code: &str, message: &str) -> AuthResponse {
    AuthResponse::json(
        status,
        &better_auth_core::ErrorCodeMessageResponse {
            message: message.to_owned(),
            code: Some(code.to_owned()),
        },
    )
    .unwrap_or_else(|_| AuthResponse::text(status, message))
}

#[derive(Default)]
pub(crate) struct SignOutBody {
    pub callback_url: Option<String>,
    pub disable_redirect: Option<bool>,
    pub state: Option<String>,
}

pub(crate) fn sign_out(req: &AuthRequest) -> Result<SignOutBody, AuthResponse> {
    let Some(body) = parse(req)? else {
        return Ok(SignOutBody::default());
    };
    let Some(body) = body.as_object() else {
        return Err(validation_error(&invalid_type(
            "body",
            "object",
            Some(&body),
        )));
    };
    let mut errors = Vec::new();
    for (field, expected) in [
        ("callbackURL", "string"),
        ("disableRedirect", "boolean"),
        ("state", "string"),
    ] {
        if let Some(value) = body.get(field)
            && type_name(Some(value)) != expected
        {
            errors.push(invalid_type(
                &format!("body.{field}"),
                expected,
                Some(value),
            ));
        }
    }
    if !errors.is_empty() {
        return Err(validation_error(&errors.join("; ")));
    }
    Ok(SignOutBody {
        callback_url: body
            .get("callbackURL")
            .and_then(Value::as_str)
            .map(str::to_owned),
        disable_redirect: body.get("disableRedirect").and_then(Value::as_bool),
        state: body.get("state").and_then(Value::as_str).map(str::to_owned),
    })
}

/// Zod's issue for `value` at `path` unless it has the `expected` type; `optional` lets
/// an absent value pass. Returns whether the value passed.
fn check(
    issues: &mut Vec<String>,
    path: &str,
    value: Option<&Value>,
    expected: &str,
    optional: bool,
) -> bool {
    let valid = optional && value.is_none()
        || match expected {
            "record" | "object" => value.is_some_and(Value::is_object),
            "array" => value.is_some_and(Value::is_array),
            _ => type_name(value) == expected,
        };
    if !valid {
        issues.push(invalid_type(&format!("body.{path}"), expected, value));
    }
    valid
}

/// The bodies of `/sign-in/social` (`link: false`) and `/link-social`, checked in their
/// Zod schemas' field order, so every issue is reported as better-auth reports it.
pub(crate) fn oauth_flow(req: &AuthRequest, link: bool) -> Result<(), AuthResponse> {
    let body = parse(req)?;
    let Some(object) = body.as_ref().and_then(Value::as_object) else {
        return Err(validation_error(&invalid_type(
            "body",
            "object",
            body.as_ref(),
        )));
    };
    let fields: &[(&str, &str)] = if link {
        &[
            ("callbackURL", "string"),
            ("provider", "provider"),
            ("idToken", "object"),
            ("requestSignUp", "boolean"),
            ("scopes", "array"),
            ("errorCallbackURL", "string"),
            ("disableRedirect", "boolean"),
            ("loginHint", "string"),
            ("additionalParams", "record"),
            ("additionalData", "record"),
        ]
    } else {
        &[
            ("callbackURL", "string"),
            ("newUserCallbackURL", "string"),
            ("errorCallbackURL", "string"),
            ("provider", "provider"),
            ("disableRedirect", "boolean"),
            ("idToken", "object"),
            ("scopes", "array"),
            ("requestSignUp", "boolean"),
            ("loginHint", "string"),
            ("additionalParams", "record"),
            ("additionalData", "record"),
        ]
    };
    let mut issues = Vec::new();
    for (name, expected) in fields {
        let value = object.get(*name);
        if *expected == "provider" {
            if !value.is_some_and(Value::is_string) {
                issues.push("[body.provider] Invalid input".to_owned());
            }
            continue;
        }
        if !check(&mut issues, name, value, expected, true) {
            continue;
        }
        let Some(value) = value else { continue };
        match *name {
            "idToken" => id_token_issues(&mut issues, value, link),
            "scopes" => {
                for (index, scope) in value.as_array().into_iter().flatten().enumerate() {
                    let _ = check(
                        &mut issues,
                        &format!("scopes.{index}"),
                        Some(scope),
                        "string",
                        false,
                    );
                }
            }
            "additionalParams" => {
                // In the body's own key order, as Zod reports them.
                let ordered = req
                    .body
                    .as_deref()
                    .and_then(|bytes| serde_json::from_slice::<OrderedParams>(bytes).ok())
                    .map(|params| params.additional_params)
                    .unwrap_or_default();
                for (key, parameter) in &ordered {
                    let _ = check(
                        &mut issues,
                        &format!("additionalParams.{key}"),
                        Some(parameter),
                        "string",
                        false,
                    );
                }
            }
            _ => {}
        }
    }
    if issues.is_empty() {
        Ok(())
    } else {
        Err(validation_error(&issues.join("; ")))
    }
}

#[derive(serde::Deserialize)]
struct OrderedParams {
    #[serde(rename = "additionalParams", default)]
    additional_params: indexmap::IndexMap<String, Value>,
}

fn id_token_issues(issues: &mut Vec<String>, value: &Value, link: bool) {
    for (field, expected) in [
        ("token", "string"),
        ("nonce", "string"),
        ("accessToken", "string"),
        ("refreshToken", "string"),
    ] {
        let _ = check(
            issues,
            &format!("idToken.{field}"),
            value.get(field),
            expected,
            field != "token",
        );
    }
    if link {
        return;
    }
    let _ = check(
        issues,
        "idToken.expiresAt",
        value.get("expiresAt"),
        "number",
        true,
    );
    if check(issues, "idToken.user", value.get("user"), "object", true)
        && let Some(user) = value.get("user")
    {
        if check(
            issues,
            "idToken.user.name",
            user.get("name"),
            "object",
            true,
        ) && let Some(name) = user.get("name")
        {
            for field in ["firstName", "lastName"] {
                let _ = check(
                    issues,
                    &format!("idToken.user.name.{field}"),
                    name.get(field),
                    "string",
                    true,
                );
            }
        }
        let _ = check(
            issues,
            "idToken.user.email",
            user.get("email"),
            "string",
            true,
        );
    }
}

/// The POST callback's body (a form post from the provider), before it redirects to GET.
pub(crate) fn oauth_callback(req: &AuthRequest) -> Result<(), AuthResponse> {
    let Some(body) = parse(req)? else {
        return Ok(());
    };
    let Some(object) = body.as_object() else {
        return Err(validation_error(&invalid_type(
            "body",
            "object",
            Some(&body),
        )));
    };
    let issues: Vec<String> = [
        "code",
        "error",
        "device_id",
        "error_description",
        "state",
        "user",
        "iss",
    ]
    .into_iter()
    .filter_map(|field| {
        object
            .get(field)
            .filter(|value| !value.is_string())
            .map(|value| invalid_type(&format!("body.{field}"), "string", Some(value)))
    })
    .collect();
    if issues.is_empty() {
        Ok(())
    } else {
        Err(validation_error(&issues.join("; ")))
    }
}
