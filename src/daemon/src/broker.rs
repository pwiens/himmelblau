/*
   Unix Azure Entra ID implementation
   Copyright (C) David Mulder <dmulder@samba.org> 2024

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use himmelblau_unix_common::access_token_cache::diagnostics::{
    self, Event, Outcome, Reason, RequestLog, Stage, REQUEST_ID,
};
use himmelblau_unix_common::access_token_cache::{
    access_token_generation, invalidate_access_tokens, CacheError, CachedResponse, IssuedToken,
};
use himmelblau_unix_common::idprovider::himmelblau::HimmelblauMultiProvider;
use himmelblau_unix_common::idprovider::interface::{Id, UserToken};
use himmelblau_unix_common::resolver::Resolver;
use identity_dbus_broker::HimmelblauBroker;
use libc::uid_t;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod cache;
use url::Url;

#[derive(Serialize, Deserialize, Debug)]
struct AccountReq {
    username: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PopParamsReq {
    #[serde(rename = "authenticationScheme")]
    authentication_scheme: Option<String>,
    kid: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AuthParametersReq {
    #[serde(rename = "requestedScopes")]
    requested_scopes: Vec<String>,
    #[serde(rename = "clientId")]
    client_id: Option<String>,
    #[serde(rename = "redirectUri")]
    redirect_uri: Option<String>,
    #[serde(rename = "popParams")]
    pop_params: Option<PopParamsReq>,
    account: Option<AccountReq>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenReq {
    account: Option<AccountReq>,
    #[serde(rename = "authParameters")]
    auth_parameters: AuthParametersReq,
}

#[derive(Serialize, Deserialize, Debug)]
struct SsoCookieReq {
    account: AccountReq,
    #[serde(rename = "ssoUrl")]
    sso_url: Option<String>,
}

/// Extract the `sso_nonce` query parameter from an SSO URL, if present.
/// Returns `None` when the parameter is missing or empty/whitespace-only.
fn extract_sso_nonce(sso_url: Option<&str>) -> Option<String> {
    let url_str = sso_url?;
    let url = Url::parse(url_str).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == "sso_nonce")
        .map(|(_, v)| v.into_owned())
        .filter(|v| !v.trim().is_empty())
}

/// Build a `req_cnf` value from the broker request's `popParams`.
/// When `popParams.authenticationScheme` is `"Pop"` and `kid` is set
/// (e.g. for RDS AAD / Cloud PC), we produce
/// `base64url({"kid":"<kid>"})` which Entra expects as the `req_cnf`
/// query / body parameter. Requests without the PoP scheme or without
/// a kid are treated as bearer token requests (returns None).
fn build_req_cnf(pop_params: &Option<PopParamsReq>) -> Option<String> {
    let pp = pop_params.as_ref()?;
    if !pp
        .authentication_scheme
        .as_deref()
        .is_some_and(|s| s.eq_ignore_ascii_case("pop"))
    {
        return None;
    }
    let kid = pp.kid.as_deref().map(str::trim).filter(|k| !k.is_empty())?;
    let json = serde_json::json!({"kid": kid}).to_string();
    Some(URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

#[derive(Clone)]
pub(crate) struct Broker {
    pub(crate) cachelayer: Arc<Resolver<HimmelblauMultiProvider>>,
}

impl Broker {
    /// This authorization runs before EVERY lookup and after every wait. The
    /// Nix multi-account patch changes only account selection in this method.
    async fn authorized_user(
        &self,
        username: &str,
        uid: uid_t,
    ) -> Result<UserToken, Box<dyn Error>> {
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        if username.to_lowercase() != user.spn.to_lowercase() {
            return Err("Invalid request for user!".into());
        }
        // The Nix selection may come from the all-account enumerator. Keep
        // the name-based resolver's exclusion and metadata-expiry checks on
        // hits too, exactly as get_user_accesstoken does on misses.
        let user = self
            .cachelayer
            .get_usertoken(Id::Name(user.spn.clone()))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        if username.to_lowercase() != user.spn.to_lowercase() {
            return Err("Invalid request for user!".into());
        }
        Ok(user)
    }
}

#[async_trait]
impl HimmelblauBroker for Broker {
    async fn acquire_token_interactively(
        &mut self,
        protocol_version: String,
        correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Explicit interactive acquisition is an authorization-context refresh,
        // never permission to return the previous silent result.
        if request_json.len() > 16 * 1024 {
            return Err("Token request too large".into());
        }
        let mut request: serde_json::Value = serde_json::from_str(&request_json)?;
        request
            .get_mut("authParameters")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("Invalid authParameters")?
            .insert("forceRefresh".into(), json!(true));
        self.acquire_token_silently(protocol_version, correlation_id, request.to_string(), uid)
            .await
    }

    async fn acquire_token_silently(
        &mut self,
        protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        let mut log = RequestLog::default();
        let result = REQUEST_ID.scope(log.id, tokio::time::timeout(Duration::from_secs(45), async {
            if request_json.len() > 16 * 1024 { return Err("Token request too large".into()); }
            let raw: serde_json::Value = serde_json::from_str(&request_json)?;
            let request: TokenReq = serde_json::from_value(raw.clone())?;
            let account = request.account.or(request.auth_parameters.account).ok_or("Missing account")?;
            log.stage = Stage::AuthorizeBefore;
            log.reason = Reason::AuthorizationDenied;
            let user = self.authorized_user(&account.username, uid).await?;
            log.stage = Stage::Admission;
            log.reason = Reason::InvalidForceRefresh;
            let policy = cache::request_policy(&raw, &user)?;
            let key = cache::key(uid, &user, &raw, &protocol_version);
            let shared = &self.cachelayer.broker_access_tokens;
            if policy.reason != Reason::Eligible {
                diagnostics::event(Event::Bypass, policy.reason, 0, Some(shared.stats()));
            }
            if policy.claims_challenge {
                log.reason = Reason::ClaimsUnsupported;
                shared.invalidate_key(&key, Reason::ClaimsChallenge)?;
                return Err("Claims challenges are not supported by this provider".into());
            }
            if policy.force_refresh && policy.reason != Reason::Eligible {
                shared.invalidate_key(&key, Reason::ForcedRefresh)?;
            }
            let generation = access_token_generation();
            log.reason = Reason::InvalidRedirect;
            let redirect_uri = match request.auth_parameters.redirect_uri {
                Some(ref uri) if !uri.trim().is_empty() => {
                    let parsed = Url::parse(uri.trim()).map_err(|_| "Invalid redirectUri")?;
                    if parsed.fragment().is_some() { return Err("Invalid redirectUri: fragment not allowed".into()); }
                    Some(uri.trim().to_string())
                }
                _ => None,
            };
            let req_cnf = build_req_cnf(&request.auth_parameters.pop_params);
            log.stage = Stage::Acquire;
            log.reason = Reason::BackendFailure;
            let acquire = || async {
                let started = SystemTime::now();
                let started_monotonic = Instant::now();
                let token = self.cachelayer.get_user_accesstoken_with_error(
                    Id::Name(user.spn.clone()), request.auth_parameters.requested_scopes,
                    request.auth_parameters.client_id.clone(), redirect_uri, req_cnf,
                ).await.map_err(|error| cache::acquisition_error(&error))?;
                let (access, scopes, id_token) = cache::response_fields(&token).map_err(|reason| {
                    diagnostics::event(Event::ResponseRejected, reason, 0, Some(shared.stats()));
                    CacheError::Acquisition
                })?;
                let expires_at = match cache::validated_expiry(&token, &user,
                    request.auth_parameters.client_id.as_deref(), started) {
                    Ok(expiry) => expiry.duration_since(started).ok()
                        .and_then(|ttl| started_monotonic.checked_add(ttl).map(|mono| (expiry, mono))),
                    Err(reason) => {
                        diagnostics::event(Event::ResponseRejected, reason, 0, Some(shared.stats()));
                        None
                    }
                };
                let now = started.duration_since(UNIX_EPOCH).map_err(|_| CacheError::Acquisition)?;
                let res = json!({"brokerTokenResponse": {
                    "accessToken": access,
                    "accessTokenType": 0,
                    "clientInfo": URL_SAFE_NO_PAD.encode(json!(&token.client_info).to_string()),
                    "expiresOn": now.as_millis() + u128::from(token.expires_in) * 1000,
                    "extendedExpiresOn": u64::from(token.ext_expires_in) + now.as_secs(),
                    "grantedScopes": scopes,
                    "idToken": id_token,
                }});
                Ok(IssuedToken { response: res.to_string().into(), expires_at })
            };
            let response = if policy.reason == Reason::Eligible {
                shared.get_or_acquire_with_policy(key, policy.force_refresh, acquire).await?
            } else {
                CachedResponse::uncached(tokio::time::timeout(Duration::from_secs(40), acquire()).await
                    .map_err(|_| CacheError::Timeout)??.response)
            };
            log.stage = Stage::AuthorizeAfter;
            log.reason = Reason::AuthorizationDenied;
            let current = self.authorized_user(&account.username, uid).await?;
            if current.uuid != user.uuid || current.tenant_id != user.tenant_id
                || current.spn != user.spn || generation != access_token_generation() {
                return Err(CacheError::Invalidated.into());
            }
            // Also fence a matching forced refresh arriving during reauthorization.
            response.validate()?;
            log.stage = Stage::Complete;
            Ok::<String, Box<dyn Error>>(response.as_str().to_owned())
        })).await;
        match result {
            Err(_) => {
                log.finish(Outcome::Timeout);
                Err(CacheError::Timeout.into())
            }
            Ok(Ok(response)) => {
                log.finish(Outcome::Success);
                Ok(response)
            }
            Ok(Err(error)) => {
                let outcome = match error.downcast_ref::<CacheError>() {
                    Some(CacheError::Invalidated) => Outcome::Invalidated,
                    Some(CacheError::Timeout) => Outcome::Timeout,
                    Some(CacheError::Busy) => {
                        log.reason = Reason::Capacity;
                        Outcome::Rejected
                    }
                    _ => Outcome::Rejected,
                };
                log.finish(outcome);
                if let Some(response) = error
                    .downcast_ref::<CacheError>()
                    .copied()
                    .and_then(cache::error_response)
                {
                    // Keep the established broker wire envelope. This is a
                    // rejected request, not a successful cached token response.
                    return Ok(response);
                }
                Err(error)
            }
        }
    }

    async fn get_accounts(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Only return the account for the requesting user
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        let res = json!({
            "accounts": [
                {
                    "environment": "login.windows.net",
                    "givenName": user.displayname,
                    "homeAccountId": format!("{}.{}", user.uuid.to_string(), user.tenant_id.map(|uuid| uuid.to_string()).unwrap_or("".to_string())),
                    "localAccountId": user.uuid.to_string(),
                    "name": user.displayname,
                    "passwordExpiry": 0,
                    "realm": user.tenant_id.map(|uuid| uuid.to_string()).unwrap_or("".to_string()),
                    "username": user.spn
                }
            ]
        });
        Ok(res.to_string())
    }

    async fn remove_account(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        let request: SsoCookieReq = serde_json::from_str(&request_json)?;
        self.authorized_user(&request.account.username, uid).await?;
        invalidate_access_tokens(Reason::AccountRemoved);
        // Account/PRT removal is still unsupported. Do not claim logout or
        // silently delete credentials, but never retain an access-token hit.
        Err("Not implemented".into())
    }

    async fn acquire_prt_sso_cookie(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        request_json: String,
        uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        // Double check the user is making a request for their own account
        let user = self
            .cachelayer
            .get_usertoken(Id::Gid(uid))
            .await
            .map_err(|_| "Unable to load account")?
            .ok_or("Unable to find account")?;
        let request: SsoCookieReq =
            serde_json::from_str(&request_json).map_err(|e| format!("{:?}", e))?;
        if request.account.username.to_lowercase() != user.spn.to_lowercase() {
            return Err("Invalid request for user!".into());
        }
        // Extract sso_nonce from the ssoUrl query parameter if present.
        // When no sso_nonce is provided (proactive SSO flow, e.g. the linux-entra-sso
        // extension setting a static header), the cookie will be generated
        // with an iat claim instead of a server nonce, giving it a longer
        // validity window.
        let sso_nonce = extract_sso_nonce(request.sso_url.as_deref());
        let prt = self
            .cachelayer
            .get_user_prt_cookie(Id::Name(user.spn.clone()), sso_nonce.as_deref())
            .await
            .ok_or("Failed to fetch prt sso cookie")?;
        let res = json!({
            "account": {
                "environment": "login.microsoftonline.com",
                "homeAccountId": format!("{}.{}", user.uuid.to_string(), user.tenant_id.map(|uuid| uuid.to_string()).unwrap_or("".to_string())),
                "localAccountId": user.uuid.to_string(),
                "realm": user.tenant_id.map(|uuid| uuid.to_string()).unwrap_or("".to_string()),
                "username": user.spn.to_string(),
            },
            "cookieContent": prt,
            "cookieName": "x-ms-RefreshTokenCredential",
        });
        Ok(res.to_string())
    }

    async fn generate_signed_http_request(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        Err("Not implemented".into())
    }

    async fn cancel_interactive_flow(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        Err("Not implemented".into())
    }

    async fn get_linux_broker_version(
        &mut self,
        _protocol_version: String,
        _correlation_id: String,
        _request_json: String,
        _uid: uid_t,
    ) -> Result<String, Box<dyn Error>> {
        let res = json!({
            "linuxBrokerVersion": env!("CARGO_PKG_VERSION"),
        });
        Ok(res.to_string())
    }
}
