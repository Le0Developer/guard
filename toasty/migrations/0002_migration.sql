ALTER TABLE "sessions" ADD COLUMN "token" TEXT NOT NULL;
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_sessions_by_token" ON "sessions" ("token");
-- #[toasty::breakpoint]
CREATE TABLE "login_sessions" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "token" TEXT NOT NULL,
    "internal_token" TEXT NOT NULL,
    "redirect_uri" TEXT,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_login_sessions_by_token" ON "login_sessions" ("token");
