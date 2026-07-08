/// Cross-tenant authorization guard.
///
/// Checks that the authenticated key's org matches the route's org_id.
/// Returns 404 (not 403) to avoid existence leaks.
/// Bootstrap/admin keys bypass the org check.
use crate::auth::AuthenticatedKey;
use axum::http::StatusCode;

/// Verify that the authenticated key's org matches the route's org_id.
/// Call this at the start of every org-scoped handler.
///
/// Returns `Err(StatusCode::NOT_FOUND)` if the orgs don't match
/// (404, not 403, to avoid leaking org existence).
pub fn verify_org(auth: &AuthenticatedKey, route_org_id: &str) -> Result<(), StatusCode> {
    if auth.is_admin {
        return Ok(());
    }
    if auth.org_id == route_org_id {
        Ok(())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_key() -> AuthenticatedKey {
        AuthenticatedKey {
            key_id: "admin".into(),
            org_id: "admin".into(),
            is_admin: true,
        }
    }

    fn org_key(org: &str) -> AuthenticatedKey {
        AuthenticatedKey {
            key_id: "key-1".into(),
            org_id: org.into(),
            is_admin: false,
        }
    }

    #[test]
    fn admin_bypasses_org_check() {
        assert!(verify_org(&admin_key(), "any-org").is_ok());
    }

    #[test]
    fn matching_org_passes() {
        assert!(verify_org(&org_key("orgA"), "orgA").is_ok());
    }

    #[test]
    fn mismatched_org_returns_not_found() {
        let result = verify_org(&org_key("orgA"), "orgB");
        assert_eq!(result.unwrap_err(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn mismatched_org_not_forbidden() {
        // Must be 404, NOT 403 — avoid leaking org existence
        let result = verify_org(&org_key("orgA"), "orgB");
        assert_ne!(result.unwrap_err(), StatusCode::FORBIDDEN);
    }
}
