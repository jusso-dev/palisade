-- One-time database bootstrap for palisade-server (#127, ADR 0006).
--
-- Run once, by a database administrator, with psql:
--
--   psql -v ON_ERROR_STOP=1 -v owner=palisade_owner -v runtime_user=palisade_app \
--        -v database=palisade -f bootstrap.sql postgres
--
-- then set a password for each login role, interactively, so it never appears in a file or in
-- the process list:
--
--   \password palisade_owner
--   \password palisade_app
--
-- It creates:
--
-- - palisade_runtime: a NOLOGIN group role. The migrations grant table privileges to it, and
--   nothing else. It is the same role for every Palisade database in the cluster.
-- - :owner, the migration role. It owns the database and, through the migrations, the schema
--   and every table. palisade-server uses it only for `migrate up` and `auto_migrate`.
-- - :runtime_user, the runtime role. It is a member of palisade_runtime and owns nothing, so
--   row-level security always applies to it.
--
-- No role here is a superuser, and none has BYPASSRLS, CREATEROLE or CREATEDB.
--
-- The statements are kept free of psql meta-commands except the single \connect line, so the
-- integration tests can run this same file.

DO $$
BEGIN
    CREATE ROLE palisade_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Two bootstraps at once can race; either error means the role now exists.
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END
$$;

CREATE ROLE :"owner" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

CREATE ROLE :"runtime_user" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

GRANT palisade_runtime TO :"runtime_user";

CREATE DATABASE :"database" OWNER :"owner" ENCODING 'UTF8' TEMPLATE template0;

REVOKE ALL ON DATABASE :"database" FROM PUBLIC;

GRANT CONNECT, TEMPORARY ON DATABASE :"database" TO :"owner";

GRANT CONNECT ON DATABASE :"database" TO palisade_runtime;

\connect :"database"

-- Nobody but the owner creates objects, in any schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
