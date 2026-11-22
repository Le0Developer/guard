ALTER TABLE "users" ADD COLUMN "role" TEXT NOT NULL CHECK ("role" IN ('user', 'admin'));
-- #[toasty::breakpoint]
CREATE TABLE "clients" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client_type" TEXT NOT NULL CHECK ("client_type" IN ('oidc', 'forward_auth')),
    "client_id" TEXT NOT NULL,
    "client_secret" TEXT NOT NULL,
    "created_at" TEXT NOT NULL,
    "updated_at" TEXT NOT NULL,
    "deleted_at" TEXT
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_clients_by_client_id" ON "clients" ("client_id");
-- #[toasty::breakpoint]
CREATE TABLE "groups" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" TEXT NOT NULL,
    "created_at" TEXT NOT NULL,
    "updated_at" TEXT NOT NULL,
    "deleted_at" TEXT
);
-- #[toasty::breakpoint]
CREATE TABLE "client_access_rules" (
    "client_id" BIGINT NOT NULL,
    "group_id" BIGINT NOT NULL,
    "priority" SMALLINT NOT NULL,
    "access_control" TEXT NOT NULL CHECK ("access_control" IN ('allow', 'deny')),
    "created_at" TEXT NOT NULL,
    PRIMARY KEY ("client_id", "group_id")
);
-- #[toasty::breakpoint]
CREATE TABLE "group_members" (
    "group_id" BIGINT NOT NULL,
    "user_id" BIGINT NOT NULL,
    "created_at" TEXT NOT NULL,
    PRIMARY KEY ("group_id", "user_id")
);
