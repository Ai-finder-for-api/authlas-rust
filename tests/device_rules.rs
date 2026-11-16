//! Device grant rules through the pure functions behind the C ABI (src/capi_device.rs).

mod rules {
    use authlas::oauth::device::{DEFAULT_INTERVAL, LIFETIME};

    fn rec(state: &str) -> authlas::oauth::device_rules::DeviceRecord {
        authlas::oauth::device_rules::DeviceRecord {
            device_hash: "h".into(),
            client_id: "tv".into(),
            scope: "read".into(),
            user_code: "BCDFGHJK".into(),
            expires_at: 10_000,
            interval: DEFAULT_INTERVAL,
            last_poll: 0,
            state: state.into(),
            subject: None,
            grant_id: "g".into(),
            failed_user_attempts: 0,
        }
    }

    #[test]
    fn pending_then_approved_then_issued_once() {
        let mut r = rec("pending");
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 100), Err("authorization_pending"));
        authlas::oauth::device_rules::decide_step(&mut r, Some("alice"), 110, 5).unwrap();
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 200), Ok(()));
        // the grant is spent: a second poll cannot issue again
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 300), Err("invalid_grant"));
    }

    #[test]
    fn fast_polling_returns_slow_down_and_raises_interval() {
        let mut r = rec("pending");
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 100), Err("authorization_pending"));
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 101), Err("slow_down"));
        assert_eq!(r.interval, DEFAULT_INTERVAL + 5);
    }

    #[test]
    fn denied_code_reports_access_denied() {
        let mut r = rec("pending");
        authlas::oauth::device_rules::decide_step(&mut r, None, 110, 5).unwrap();
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 200), Err("access_denied"));
    }

    #[test]
    fn expired_code_is_refused() {
        let mut r = rec("approved");
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "tv", 10_000), Err("expired_token"));
    }

    #[test]
    fn another_client_cannot_poll() {
        let mut r = rec("approved");
        assert_eq!(authlas::oauth::device_rules::poll_step(&mut r, "attacker", 200), Err("invalid_grant"));
        assert_eq!(r.state, "approved", "a wrong client must not consume the grant");
    }

    #[test]
    fn attempt_limit_closes_the_code() {
        let mut r = rec("pending");
        r.failed_user_attempts = 5;
        assert!(authlas::oauth::device_rules::decide_step(&mut r, Some("mallory"), 110, 5).is_err());
        assert_eq!(r.state, "pending", "an exhausted code must not be approved");
    }

    #[test]
    fn decision_after_expiry_is_refused() {
        let mut r = rec("pending");
        assert!(authlas::oauth::device_rules::decide_step(&mut r, Some("alice"), 10_000, 5).is_err());
    }

    #[test]
    fn lifetime_matches_rfc_draft_default() {
        assert_eq!(LIFETIME, 600);
    }
}
