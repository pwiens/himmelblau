//! Preserve structured Entra token-exchange codes without leaking arbitrary
//! server/transport descriptions into the broker protocol or shared cache.
use super::interface::IdpError;
use himmelblau::error::MsalError;

/// Only token-exchange callers use this mapping. PAM authentication, provider
/// reachability, group resolution, and other state-machine paths do not.
pub(crate) fn from_msal(error: MsalError) -> IdpError {
    let code = match error {
        MsalError::AcquireTokenFailed(error) => {
            // A loop rejection is terminal even if the server also supplies
            // another code. Clients must not amplify it with fallback traffic.
            if error.error_codes.contains(&50196) {
                Some(50196)
            } else {
                error.error_codes.into_iter().find(|code| *code != 0)
            }
        }
        MsalError::AADSTSError(error) => Some(error.code).filter(|code| *code != 0),
        _ => None,
    };
    match code {
        Some(aadsts_code) => IdpError::TokenAcquisition { aadsts_code },
        None => IdpError::BadRequest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use himmelblau::error::{AADSTSError, ErrorResponse};

    fn response(codes: Vec<u32>) -> MsalError {
        MsalError::AcquireTokenFailed(ErrorResponse {
            error: "SECRET_ERROR".into(),
            error_description: "SECRET_TOKEN https://private.example/?claims=SECRET".into(),
            suberror: Some("SECRET_SUBERROR".into()),
            error_codes: codes,
        })
    }

    #[test]
    fn structured_codes_survive_but_server_text_never_does() {
        for code in [50196, 50076, 65001, 50011, 123456] {
            let error = from_msal(response(vec![code]));
            assert!(
                matches!(error, IdpError::TokenAcquisition { aadsts_code } if aadsts_code == code)
            );
            let text = format!("{error:?}");
            assert!(!text.contains("SECRET"));
            assert!(!text.contains("https://"));
            assert!(matches!(
                from_msal(MsalError::AADSTSError(AADSTSError::new(code, None))),
                IdpError::TokenAcquisition { aadsts_code } if aadsts_code == code
            ));
        }
        assert!(matches!(
            from_msal(response(vec![50076, 50196])),
            IdpError::TokenAcquisition { aadsts_code: 50196 }
        ));
    }

    #[test]
    fn opaque_text_is_not_promoted_to_a_structured_auth_failure() {
        for error in [
            response(vec![]),
            response(vec![0]),
            MsalError::RequestFailed("AADSTS50196 SECRET_TOKEN".into()),
            MsalError::InvalidJson("AADSTS50196 SECRET_TOKEN".into()),
            MsalError::ConfigError("SECRET_CONFIG".into()),
            MsalError::TPMFail("SECRET_KEY".into()),
            MsalError::AuthTypeUnsupported,
        ] {
            assert!(matches!(from_msal(error), IdpError::BadRequest));
        }
    }
}
