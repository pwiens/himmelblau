//! Conservative cache admission for the pinned provider (not a token validator
//! for arbitrary input). Responses originate from its authenticated TLS exchange.
use super::*;
use himmelblau::auth::UserToken as Issued;
use serde_json::Value;
use uuid::Uuid;

pub(super) fn key(uid: uid_t, user: &UserToken, raw: &Value, protocol: &str) -> String {
    json!([uid, user.uuid, user.tenant_id, user.spn, protocol, raw]).to_string()
}

pub(super) struct RequestPolicy {
    pub cacheable: bool,
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
    // No claims/PoP/unknown extension can hit a plain bearer entry. Exact raw
    // values (including scopes, redirect, flow fields) remain in the key.
    let mut cacheable = known_fields(raw, &["account", "authParameters"])
        && known_fields(
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
        && user.tenant_id.is_some()
        && user.valid
        && !claims_challenge;
    for account in [raw.get("account"), auth.get("account")]
        .into_iter()
        .flatten()
        .filter(|v| !v.is_null())
    {
        cacheable &= known_fields(
            account,
            &[
                "username",
                "homeAccountId",
                "localAccountId",
                "realm",
                "environment",
            ],
        );
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
                cacheable &= value.as_str() == Some(expected.as_str());
            }
        }
        cacheable &= account["username"]
            .as_str()
            .is_some_and(|name| name.to_lowercase() == user.spn.to_lowercase());
    }
    if let Some(authority) = auth.get("authority") {
        // The provider resolves its HOME tenant independently. Do not certify a
        // requested TME/guest/cloud authority as matching that home response.
        cacheable &= authority
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
            });
    }
    Ok(RequestPolicy {
        cacheable,
        force_refresh,
        claims_challenge,
    })
}

pub(super) fn validated_expiry(
    token: &Issued,
    user: &UserToken,
    client: Option<&str>,
    started: SystemTime,
) -> Option<SystemTime> {
    // Cache only identity-bound bearer results. This also excludes the pinned
    // refresh-token fallback when it ignores an on-behalf-of client id.
    let tenant = user.tenant_id?;
    if !token.token_type.eq_ignore_ascii_case("bearer")
        || Uuid::parse_str(&token.id_token.oid).ok()? != user.uuid
        || Uuid::parse_str(&token.id_token.tid).ok()? != tenant
        || token.expires_in == 0
    {
        return None;
    }
    let access = token.access_token.as_ref()?;
    let payload = access.split('.').nth(1)?;
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()?;
    if Uuid::parse_str(claims["tid"].as_str()?).ok()? != tenant
        || Uuid::parse_str(claims["oid"].as_str()?).ok()? != user.uuid
    {
        return None;
    }
    let app = claims
        .get("azp")
        .or_else(|| claims.get("appid"))?
        .as_str()?;
    if Uuid::parse_str(app).ok()? != Uuid::parse_str(client?).ok()? {
        return None;
    }
    let jwt_expiry = UNIX_EPOCH.checked_add(Duration::from_secs(claims["exp"].as_u64()?))?;
    // expires_in is documented seconds. Use the earlier bound, measured from
    // BEFORE exchange (conservative), not the historically quirky expiresOn.
    Some(jwt_expiry.min(started.checked_add(Duration::from_secs(u64::from(token.expires_in)))?))
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
    fn admission_never_confuses_challenges_pop_unknown_or_other_tenant() {
        let user = user();
        assert!(request_policy(&request(), &user).unwrap().cacheable);
        for (field, value) in [
            ("claims", json!("{}")),
            ("popParams", json!({"kid":"key"})),
            ("unknownBinding", json!(true)),
            (
                "authority",
                json!("https://login.microsoftonline.com/44444444-4444-4444-4444-444444444444"),
            ),
            (
                "authority",
                json!("https://untrusted.example/22222222-2222-2222-2222-222222222222"),
            ),
        ] {
            let mut raw = request();
            raw["authParameters"][field] = value;
            assert!(!request_policy(&raw, &user).unwrap().cacheable);
        }
        let mut raw = request();
        raw["authParameters"]["forceRefresh"] = json!(true);
        assert!(request_policy(&raw, &user).unwrap().force_refresh);
        raw["authParameters"]["forceRefresh"] = json!("true");
        assert!(request_policy(&raw, &user).is_err());
    }
    #[test]
    fn exact_keys_partition_every_authorization_and_issuance_dimension() {
        let user = user();
        let raw = request();
        let base = key(1000, &user, &raw, "1.0");
        assert!(base != key(1001, &user, &raw, "1.0"));
        assert!(base != key(1000, &user, &raw, "2.0"));
        for field in [
            "clientId",
            "authority",
            "requestedScopes",
            "claims",
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
    fn expiry_requires_matching_identity_client_and_authoritative_bounds() {
        let user = user();
        let client = "33333333-3333-3333-3333-333333333333";
        let start = UNIX_EPOCH + Duration::from_secs(1000);
        let jwt = format!(
            "e30.{}.fixture",
            URL_SAFE_NO_PAD.encode(
                json!({"tid":user.tenant_id,
            "appid":client,"oid":user.uuid,"exp":1400})
                .to_string()
            )
        );
        let mut token: Issued =
            serde_json::from_value(json!({"token_type":"Bearer","scope":"read",
            "expires_in":600,"ext_expires_in":600,"access_token":jwt,"refresh_token":"",
            "id_token":{"name":"Fixture","oid":user.uuid,"tid":user.tenant_id}}))
            .unwrap();
        assert!(
            validated_expiry(&token, &user, Some(client), start)
                == Some(UNIX_EPOCH + Duration::from_secs(1400))
        );
        token.expires_in = 200;
        assert!(
            validated_expiry(&token, &user, Some(client), start)
                == Some(UNIX_EPOCH + Duration::from_secs(1200))
        );
        assert!(validated_expiry(
            &token,
            &user,
            Some("44444444-4444-4444-4444-444444444444"),
            start
        )
        .is_none());
        token.expires_in = 0;
        assert!(validated_expiry(&token, &user, Some(client), start).is_none());
        token.expires_in = 600;
        token.access_token = Some("opaque".into());
        assert!(validated_expiry(&token, &user, Some(client), start).is_none());
    }
}
