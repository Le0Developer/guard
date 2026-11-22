ALTER TABLE "clients" ADD COLUMN "slug" TEXT NOT NULL DEFAULT '';
-- #[toasty::breakpoint]
ALTER TABLE "clients" ADD COLUMN "session_lifetime_s" INTEGER NOT NULL DEFAULT 64800;
-- #[toasty::breakpoint]
ALTER TABLE "clients" ADD COLUMN "require_pkce" BOOLEAN NOT NULL DEFAULT TRUE;
-- #[toasty::breakpoint]
UPDATE "clients" SET "slug" = 'client-' || "id" WHERE "slug" = '';
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_clients_by_slug" ON "clients" ("slug");
-- #[toasty::breakpoint]
CREATE INDEX "index_client_redirects_by_client_id" ON "client_redirects" ("client_id");
-- #[toasty::breakpoint]
ALTER TABLE "users" ADD COLUMN "email" TEXT;
-- #[toasty::breakpoint]
CREATE TABLE "o_auth_tokens" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client_id" BIGINT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "session_id" BIGINT NOT NULL,
    "code_id" BIGINT NOT NULL,
    "family" TEXT NOT NULL,
    "access_token" TEXT NOT NULL,
    "refresh_token" TEXT NOT NULL,
    "scope" TEXT NOT NULL,
    "nonce" TEXT,
    "auth_time" BIGINT NOT NULL,
    "access_expires_at" TEXT NOT NULL,
    "expires_at" TEXT NOT NULL,
    "revoked_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_o_auth_tokens_by_client_id" ON "o_auth_tokens" ("client_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_o_auth_tokens_by_code_id" ON "o_auth_tokens" ("code_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_o_auth_tokens_by_family" ON "o_auth_tokens" ("family");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_o_auth_tokens_by_access_token" ON "o_auth_tokens" ("access_token");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_o_auth_tokens_by_refresh_token" ON "o_auth_tokens" ("refresh_token");
-- #[toasty::breakpoint]
CREATE TABLE "client_tokens" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client_id" BIGINT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "token" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "pkce_challenge" BOOLEAN,
    "pkce_challenge_code" TEXT,
    "pkce_challenge_method" TEXT CHECK ("pkce_challenge_method" IN ('plain', 's256')),
    "scope" TEXT NOT NULL,
    "nonce" TEXT,
    "session_id" BIGINT NOT NULL,
    "expires_at" TEXT NOT NULL,
    "consumed_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_client_tokens_by_client_id" ON "client_tokens" ("client_id");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_client_tokens_by_token" ON "client_tokens" ("token");
-- #[toasty::breakpoint]
CREATE TABLE "client_cryptographic_keys" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client_id" BIGINT NOT NULL,
    "key" TEXT NOT NULL,
    "created_at" TEXT NOT NULL,
    "expires_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE INDEX "index_client_cryptographic_keys_by_client_id" ON "client_cryptographic_keys" ("client_id");
