CREATE UNIQUE INDEX "index_users_by_username" ON "users" ("username");
-- #[toasty::breakpoint]
PRAGMA foreign_keys = OFF;
-- #[toasty::breakpoint]
CREATE TABLE "_toasty_new_audit_logs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "user_id" BIGINT NOT NULL,
    "data" TEXT NOT NULL,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
INSERT INTO "_toasty_new_audit_logs" ("id", "user_id", "data", "created_at") SELECT "id", "user_id", "data", "created_at" FROM "audit_logs";
-- #[toasty::breakpoint]
DROP TABLE "audit_logs";
-- #[toasty::breakpoint]
ALTER TABLE "_toasty_new_audit_logs" RENAME TO "audit_logs";
-- #[toasty::breakpoint]
PRAGMA foreign_keys = ON;
