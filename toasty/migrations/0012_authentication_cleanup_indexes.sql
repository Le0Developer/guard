CREATE INDEX "index_event_report_rates_by_window" ON "event_report_rates" ("window");
-- #[toasty::breakpoint]
CREATE INDEX "index_forward_auth_sessions_by_expires_at" ON "forward_auth_sessions" ("expires_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_mfa_ceremonies_by_expires_at" ON "mfa_ceremonies" ("expires_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_recovery_codes_by_used_at" ON "recovery_codes" ("used_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_o_auth_tokens_by_expires_at" ON "o_auth_tokens" ("expires_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_client_cryptographic_keys_by_expires_at" ON "client_cryptographic_keys" ("expires_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_client_tokens_by_expires_at" ON "client_tokens" ("expires_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_login_sessions_by_created_at" ON "login_sessions" ("created_at");
-- #[toasty::breakpoint]
CREATE INDEX "index_sessions_by_created_at" ON "sessions" ("created_at");
