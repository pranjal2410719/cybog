-- add_management_user.sql
-- Run this against the Cybog SQLite DB (backend/data/cybog.db)
-- Replace <NAME> with the desired full name of the management user.
-- The UID will be generated automatically as a UUID (SQLite has no native UUID, so we use a random string).

BEGIN TRANSACTION;

-- Insert a new management user. Adjust the UID if you need a specific one.
INSERT INTO users (uid, name, role, active, created_at)
VALUES (
    -- You can let SQLite generate a random string, but here we use a simple UUID placeholder.
    -- Replace the value below with a real UUID if you prefer (e.g., using python uuid4).
    'USR-' || substr(hex(randomblob(4)), 1, 8),
    '<NAME>',
    'MANAGEMENT',
    1,
    datetime('now')
);

COMMIT;
