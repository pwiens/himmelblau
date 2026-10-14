//! Admission diagnostics are enums, never token/request data. MSAL uses trusted
//! endpoint/account metadata; this provider ignores requested authority and its
//! RT fallback can ignore client ID, so retain conservative response validation.
use super::*;
use himmelblau::auth::UserToken as Issued;
use himmelblau_unix_common::access_token_cache::diagnostics::Reason;
use himmelblau_unix_common::idprovider::interface::IdpError;
use serde_json::Value;
use uuid::Uuid;

pub(super) fn acquisition_error(error: &IdpError) -> CacheError {
    match error {
        IdpError::TokenAcquisition { aadsts_code } if *aadsts_code != 0 => {
            CacheError::Entra(*aadsts_code)
        }
        _ => CacheError::Acquisition,
    }
}

/// Structured broker error, not a token response to be stored as a cache hit.
/// Keep status unspecified rather than inventing NTSTATUS mappings. Clients
/// can use subStatus, which contains the original structured AADSTS code.
pub(super) fn error_response(error: CacheError) -> Option<String> {
    match error {
        CacheError::Entra(code) => Some(
            json!({"brokerTokenResponse": {"error": {
                "status": 0,
                "subStatus": code,
                "context": error.to_string(),
            }}})
            .to_string(),
        ),
        _ => None,
    }
}

pub(super) fn key(uid: uid_t, user: &UserToken, raw: &Value, protocol: &str) -> String {
    let mut context = raw.clone();
    // Acquisition policy isn't token identity (MSAL force_refresh semantics).
    // Claims aren't supported for issuance; omit them ONLY to invalidate the
    // corresponding plain request before rejecting the challenge.
    if let Some(root) = context.as_object_mut() {
        root.remove("claims");
    }
    if let Some(auth) = context
        .get_mut("authParameters")
        .and_then(Value::as_object_mut)
    {
        auth.remove("forceRefresh");
        auth.remove("claims");
    }
    json!([uid, user.uuid, user.tenant_id, user.spn, protocol, context]).to_string()
}
pub(super) struct RequestPolicy {
    pub reason: Reason,
    pub force_refresh: bool,
    pub claims_challenge: bool,
}
fn known_fields(value: &Value, fields: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| fields.contains(&key.as_str())))
}
pub(super) fn request_policy(
    raw: &Value,
    user: &UserToken,
) -> Result<RequestPolicy, Box<dyn Error>> {
    let auth = &raw["authParameters"];
    let force_refresh = match auth.get("forceRefresh") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        _ => return Err("Invalid forceRefresh".into()),
    };
    let claims_challenge = auth.get("claims").is_some_and(|v| !v.is_null())
        || raw.get("claims").is_some_and(|v| !v.is_null());
    Ok(RequestPolicy {
        reason: request_admission(raw, user, claims_challenge),
        force_refresh,
        claims_challenge,
    })
}
fn request_admission(raw: &Value, user: &UserToken, claims: bool) -> Reason {
    let auth = &raw["authParameters"];
    if claims {
        return Reason::ClaimsUnsupported;
    }
    if auth.get("popParams").is_some_and(|v| !v.is_null()) {
        return Reason::PopUnsupported;
    }
    if !known_fields(raw, &["account", "authParameters"])
        || !known_fields(
            auth,
            &[
                "account",
                "authority",
                "clientId",
                "redirectUri",
                "requestedScopes",
                "authorizationType",
                "username",
                "uxContextHandle",
                "forceRefresh",
            ],
        )
    {
        return Reason::UnknownParameter;
    }
    if user.tenant_id.is_none() || !user.valid {
        return Reason::AccountUnusable;
    }
    for account in [raw.get("account"), auth.get("account")]
        .into_iter()
        .flatten()
        .filter(|v| !v.is_null())
    {
        if !known_fields(
            account,
            &[
                "username",
                "homeAccountId",
                "localAccountId",
                "realm",
                "environment",
            ],
        ) {
            return Reason::UnknownParameter;
        }
        for (field, expected) in [
            ("localAccountId", user.uuid.to_string()),
            (
                "realm",
                user.tenant_id.map(|id| id.to_string()).unwrap_or_default(),
            ),
            (
                "homeAccountId",
                format!(
                    "{}.{}",
                    user.uuid,
                    user.tenant_id.map(|id| id.to_string()).unwrap_or_default()
                ),
            ),
        ] {
            if let Some(value) = account.get(field) {
                if value.as_str() != Some(expected.as_str()) {
                    return Reason::AccountMetadataMismatch;
                }
            }
        }
        if !account["username"]
            .as_str()
            .is_some_and(|name| name.to_lowercase() == user.spn.to_lowercase())
        {
            return Reason::AccountMetadataMismatch;
        }
    }
    if let Some(authority) = auth.get("authority") {
        if !authority
            .as_str()
            .and_then(|s| Url::parse(s).ok())
            .is_some_and(|url| {
                url.scheme() == "https"
                    && url.host_str() == Some("login.microsoftonline.com")
                    && url.port().is_none()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && Uuid::parse_str(url.path().trim_start_matches('/')).ok() == user.tenant_id
            })
        {
            return Reason::AuthorityMismatch;
        }
    }
    Reason::Eligible
}
pub(super) fn response_fields(token: &Issued) -> Result<(&str, &str, &str), Reason> {
    let access = token
        .access_token
        .as_deref()
        .ok_or(Reason::AccessTokenMissing)?;
    let scope = token.scope.as_deref().ok_or(Reason::GrantedScopesMissing)?;
    let id = token
        .id_token
        .raw
        .as_deref()
        .ok_or(Reason::RawIdTokenMissing)?;
    Ok((access, scope, id))
}

pub(super) fn validated_expiry(
    token: &Issued,
    user: &UserToken,
    client: Option<&str>,
    started: SystemTime,
) -> Result<SystemTime, Reason> {
    let tenant = user.tenant_id.ok_or(Reason::AccountUnusable)?;
    if !token.token_type.eq_ignore_ascii_case("bearer") {
        return Err(Reason::NonBearer);
    }
    if Uuid::parse_str(&token.id_token.oid).map_err(|_| Reason::IdIdentityMissing)? != user.uuid {
        return Err(Reason::IdIdentityMismatch);
    }
    if Uuid::parse_str(&token.id_token.tid).map_err(|_| Reason::IdTenantMissing)? != tenant {
        return Err(Reason::IdTenantMismatch);
    }
    if token.expires_in == 0 {
        return Err(Reason::UnknownExpiry);
    }
    let payload = token
        .access_token
        .as_ref()
        .and_then(|s| s.split('.').nth(1))
        .ok_or(Reason::AccessClaimsUnreadable)?;
    let claims: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| Reason::AccessClaimsUnreadable)?,
    )
    .map_err(|_| Reason::AccessClaimsUnreadable)?;
    let id = |field: &str| claims[field].as_str().and_then(|s| Uuid::parse_str(s).ok());
    if id("tid").ok_or(Reason::AccessTenantMissing)? != tenant {
        return Err(Reason::AccessTenantMismatch);
    }
    if id("oid").ok_or(Reason::AccessIdentityMissing)? != user.uuid {
        return Err(Reason::AccessIdentityMismatch);
    }
    let app = id(if claims.get("azp").is_some() {
        "azp"
    } else {
        "appid"
    })
    .ok_or(Reason::ClientMissing)?;
    if Some(app) != client.and_then(|s| Uuid::parse_str(s).ok()) {
        return Err(Reason::ClientMismatch);
    }
    let jwt_expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(
            claims["exp"].as_u64().ok_or(Reason::JwtExpiryMissing)?,
        ))
        .ok_or(Reason::UnknownExpiry)?;
    Ok(jwt_expiry.min(
        started
            .checked_add(Duration::from_secs(u64::from(token.expires_in)))
            .ok_or(Reason::UnknownExpiry)?,
    ))
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn user() -> UserToken {
        serde_json::from_value(json!({"name":"fixture", "spn":"fixture@example.test",
            "uuid":"11111111-1111-1111-1111-111111111111", "gidnumber":1000,
            "displayname":"Fixture", "shell":null, "groups":[], "valid":true,
            "tenant_id":"22222222-2222-2222-2222-222222222222"}))
        .unwrap()
    }
    fn request() -> Value {
        json!({"account":{"username":"fixture@example.test"},"authParameters":{
            "clientId":"33333333-3333-3333-3333-333333333333", "requestedScopes":["resource/.default"],
            "authority":"https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222"}})
    }
    #[test]
    fn provider_code_reaches_the_broker_error_envelope() {
        let error = acquisition_error(&IdpError::TokenAcquisition { aadsts_code: 50196 });
        assert_eq!(error, CacheError::Entra(50196));
        let wire: Value = serde_json::from_str(&error_response(error).unwrap()).unwrap();
        let response = &wire["brokerTokenResponse"];
        assert!(response.get("accessToken").is_none());
        assert_eq!(response["error"]["status"], 0);
        assert_eq!(response["error"]["subStatus"], 50196);
        assert_eq!(
            response["error"]["context"],
            "Entra token acquisition failed (AADSTS50196)"
        );
        for error in [
            IdpError::BadRequest,
            IdpError::Transport,
            IdpError::TokenAcquisition { aadsts_code: 0 },
        ] {
            let mapped = acquisition_error(&error);
            assert_eq!(mapped, CacheError::Acquisition);
            assert!(error_response(mapped).is_none());
        }
    }

    #[test]
    fn admission_reasons_are_specific_and_unknown_context_never_hits() {
        let user = user();
        assert_eq!(
            request_policy(&request(), &user).unwrap().reason,
            Reason::Eligible
        );
        for (field, value, expected) in [
            ("claims", json!("SECRET CLAIM"), Reason::ClaimsUnsupported),
            (
                "popParams",
                json!({"kid":"SECRET KEY"}),
                Reason::PopUnsupported,
            ),
            ("unknownBinding", json!(true), Reason::UnknownParameter),
            (
                "authority",
                json!("https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444"),
                Reason::AuthorityMismatch,
            ),
            (
                "authority",
                json!("https://untrusted.example/22222222-2222-2222-2222-222222222222"),
                Reason::AuthorityMismatch,
            ),
        ] {
            let mut raw = request();
            raw["authParameters"][field] = value;
            assert_eq!(request_policy(&raw, &user).unwrap().reason, expected);
        }
        let mut raw = request();
        raw["authParameters"]["forceRefresh"] = json!("true");
        assert!(request_policy(&raw, &user).is_err());
        let mut raw = request();
        raw["account"]["realm"] = json!("other");
        assert_eq!(
            request_policy(&raw, &user).unwrap().reason,
            Reason::AccountMetadataMismatch
        );
        let mut invalid = user.clone();
        invalid.valid = false;
        assert_eq!(
            request_policy(&request(), &invalid).unwrap().reason,
            Reason::AccountUnusable
        );
    }
    #[test]
    fn force_is_acquisition_policy_and_claims_only_identify_entry_for_invalidation() {
        let user = user();
        let raw = request();
        let base = key(1000, &user, &raw, "1.0");
        let mut forced = raw.clone();
        forced["authParameters"]["forceRefresh"] = json!(true);
        assert!(base == key(1000, &user, &forced, "1.0"));
        assert!(request_policy(&forced, &user).unwrap().force_refresh);
        forced["authParameters"]["claims"] = json!("SECRET CLAIM");
        assert!(base == key(1000, &user, &forced, "1.0"));
        assert!(request_policy(&forced, &user).unwrap().claims_challenge);
    }
    #[test]
    fn exact_keys_partition_authorization_and_issuance_dimensions() {
        let user = user();
        let raw = request();
        let base = key(1000, &user, &raw, "1.0");
        assert!(base != key(1001, &user, &raw, "1.0"));
        assert!(base != key(1000, &user, &raw, "2.0"));
        for field in [
            "clientId",
            "authority",
            "requestedScopes",
            "popParams",
            "redirectUri",
            "authorizationType",
        ] {
            let mut changed = raw.clone();
            changed["authParameters"][field] = json!(["different"]);
            assert!(base != key(1000, &user, &changed, "1.0"));
        }
        let mut changed = user.clone();
        changed.uuid = Uuid::nil();
        assert!(base != key(1000, &changed, &raw, "1.0"));
        changed = user.clone();
        changed.tenant_id = Some(Uuid::nil());
        assert!(base != key(1000, &changed, &raw, "1.0"));
        changed = user.clone();
        changed.spn = "other@example.test".into();
        assert!(base != key(1000, &changed, &raw, "1.0"));
    }
    #[test]
    fn response_reasons_and_earlier_expiry_bound() {
        let user = user();
        let client = "33333333-3333-3333-3333-333333333333";
        let start = UNIX_EPOCH + Duration::from_secs(1000);
        let jwt = format!(
            "e30.{}.fixture",
            URL_SAFE_NO_PAD.encode(
                json!({"tid":user.tenant_id,"appid":client,"oid":user.uuid,"exp":1400}).to_string()
            )
        );
        let mut token: Issued = serde_json::from_value(
            json!({"token_type":"Bearer","scope":"read","expires_in":600,
            "ext_expires_in":600,"access_token":jwt,"refresh_token":"",
            "id_token":{"name":"Fixture","oid":user.uuid,"tid":user.tenant_id}}),
        )
        .unwrap();
        assert!(matches!(
            response_fields(&token),
            Err(Reason::RawIdTokenMissing)
        ));
        token.id_token.raw = Some("SYNTHETIC_ID_TOKEN".into());
        assert!(response_fields(&token).is_ok());
        let mut missing = token.clone();
        missing.access_token = None;
        assert!(matches!(
            response_fields(&missing),
            Err(Reason::AccessTokenMissing)
        ));
        let mut missing = token.clone();
        missing.scope = None;
        assert!(matches!(
            response_fields(&missing),
            Err(Reason::GrantedScopesMissing)
        ));
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Ok(UNIX_EPOCH + Duration::from_secs(1400))
        );
        token.expires_in = 200;
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Ok(UNIX_EPOCH + Duration::from_secs(1200))
        );
        assert_eq!(
            validated_expiry(
                &token,
                &user,
                Some("44444444-4444-4444-4444-444444444444"),
                start
            ),
            Err(Reason::ClientMismatch)
        );
        token.expires_in = 0;
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Err(Reason::UnknownExpiry)
        );
        token.expires_in = 600;
        token.access_token = Some("opaque".into());
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Err(Reason::AccessClaimsUnreadable)
        );
        token.id_token.tid = Uuid::nil().to_string();
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Err(Reason::IdTenantMismatch)
        );
        token.id_token.oid = Uuid::nil().to_string();
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Err(Reason::IdIdentityMismatch)
        );
        token.token_type = "PoP".into();
        assert_eq!(
            validated_expiry(&token, &user, Some(client), start),
            Err(Reason::NonBearer)
        );
    }
}
