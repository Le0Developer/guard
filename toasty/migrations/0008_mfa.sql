ALTER TABLE "users" ADD COLUMN "mfa_failures" INTEGER NOT NULL DEFAULT 0;
-- #[toasty::breakpoint]
ALTER TABLE "users" ADD COLUMN "mfa_window" TEXT;
-- #[toasty::breakpoint]
ALTER TABLE "users" ADD COLUMN "webauthn_user_id" TEXT;
-- #[toasty::breakpoint]
ALTER TABLE "users" ADD COLUMN "mfa_revision" BIGINT NOT NULL DEFAULT 0;
-- #[toasty::breakpoint]
CREATE TABLE "mfa_ceremonies" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "token_hash" TEXT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "actor_id" BIGINT NOT NULL,
    "session_id" BIGINT,
    "login_session_id" BIGINT,
    "revision" BIGINT NOT NULL,
    "purpose" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "expires_at" TEXT NOT NULL,
    "consumed_at" TEXT,
    "attempts" INTEGER NOT NULL,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_mfa_ceremonies_by_token_hash" ON "mfa_ceremonies" ("token_hash");
-- #[toasty::breakpoint]
CREATE INDEX "index_mfa_ceremonies_by_user_id" ON "mfa_ceremonies" ("user_id");
-- #[toasty::breakpoint]
CREATE TABLE "recovery_codes" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" BIGINT NOT NULL,
    "hash" TEXT NOT NULL,
    "used_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_recovery_codes_by_user_id" ON "recovery_codes" ("user_id");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_recovery_codes_by_hash" ON "recovery_codes" ("hash");
-- #[toasty::breakpoint]
CREATE TABLE "webauthn_credentials" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" BIGINT NOT NULL,
    "credential_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "credential" TEXT NOT NULL,
    "sign_count" INTEGER NOT NULL,
    "last_used_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_webauthn_credentials_by_user_id" ON "webauthn_credentials" ("user_id");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_webauthn_credentials_by_credential_id" ON "webauthn_credentials" ("credential_id");
-- #[toasty::breakpoint]
CREATE TABLE "totp_authenticators" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" BIGINT NOT NULL,
    "name" TEXT NOT NULL,
    "secret" TEXT NOT NULL,
    "last_step" BIGINT NOT NULL,
    "last_used_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_totp_authenticators_by_user_id" ON "totp_authenticators" ("user_id");
