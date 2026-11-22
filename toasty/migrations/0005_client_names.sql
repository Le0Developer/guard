ALTER TABLE "clients" ADD COLUMN "name" TEXT NOT NULL DEFAULT '';
-- #[toasty::breakpoint]
UPDATE "clients" SET "name" = "client_id" WHERE "name" = '';
