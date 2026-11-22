CREATE TABLE "client_redirects" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "client_id" BIGINT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "created_at" TEXT NOT NULL
);
