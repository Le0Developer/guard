CREATE TABLE "forward_auth_sessions" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "token_hash" TEXT NOT NULL,
    "client_id" BIGINT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "session_id" BIGINT NOT NULL,
    "origin" TEXT NOT NULL,
    "expires_at" TEXT NOT NULL,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_forward_auth_sessions_by_token_hash" ON "forward_auth_sessions" ("token_hash");
-- #[toasty::breakpoint]
CREATE INDEX "index_forward_auth_sessions_by_client_id" ON "forward_auth_sessions" ("client_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_forward_auth_sessions_by_session_id" ON "forward_auth_sessions" ("session_id");
-- #[toasty::breakpoint]
CREATE TABLE "forward_auth_requests" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "state_hash" TEXT NOT NULL,
    "browser_hash" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "client_id" BIGINT NOT NULL,
    "origin" TEXT NOT NULL,
    "return_uri" TEXT NOT NULL,
    "user_id" BIGINT,
    "session_id" BIGINT,
    "expires_at" TEXT NOT NULL,
    "consumed_at" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_forward_auth_requests_by_state_hash" ON "forward_auth_requests" ("state_hash");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_forward_auth_requests_by_code_hash" ON "forward_auth_requests" ("code_hash");
-- #[toasty::breakpoint]
CREATE INDEX "index_forward_auth_requests_by_client_id" ON "forward_auth_requests" ("client_id");
