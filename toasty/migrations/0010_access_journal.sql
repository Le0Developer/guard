ALTER TABLE "clients" ADD COLUMN "allow_event_reports" BOOLEAN NOT NULL DEFAULT FALSE;
-- #[toasty::breakpoint]
ALTER TABLE "clients" ADD COLUMN "detailed_logging" BOOLEAN NOT NULL DEFAULT FALSE;
-- #[toasty::breakpoint]
CREATE TABLE "access_logs" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "event_id" TEXT NOT NULL,
    "dedupe_key" TEXT NOT NULL,
    "client_id" BIGINT NOT NULL,
    "user_id" BIGINT,
    "session_id" BIGINT,
    "source" TEXT NOT NULL,
    "data" TEXT NOT NULL,
    "created_at" TEXT NOT NULL
);
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_access_logs_by_event_id" ON "access_logs" ("event_id");
-- #[toasty::breakpoint]
CREATE UNIQUE INDEX "index_access_logs_by_dedupe_key" ON "access_logs" ("dedupe_key");
-- #[toasty::breakpoint]
CREATE INDEX "index_access_logs_by_client_id" ON "access_logs" ("client_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_access_logs_by_user_id" ON "access_logs" ("user_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_access_logs_by_session_id" ON "access_logs" ("session_id");
-- #[toasty::breakpoint]
CREATE INDEX "index_access_logs_by_source" ON "access_logs" ("source");
-- #[toasty::breakpoint]
CREATE TABLE "access_log_deliveries" (
    "log_id" BIGINT NOT NULL,
    "attempts" INTEGER NOT NULL,
    "next_attempt_at" TEXT NOT NULL,
    "delivered_at" TEXT,
    "last_error" TEXT,
    PRIMARY KEY ("log_id")
);
-- #[toasty::breakpoint]
CREATE INDEX "index_access_log_deliveries_by_next_attempt_at" ON "access_log_deliveries" ("next_attempt_at");
-- #[toasty::breakpoint]
CREATE TABLE "event_report_rates" (
    "client_id" BIGINT NOT NULL,
    "window" BIGINT NOT NULL,
    "count" INTEGER NOT NULL,
    PRIMARY KEY ("client_id")
);
