-- Schema foundations (#127, ADR 0006). Runs as the migration (owner) role.
--
-- palisade-server creates the `palisade` schema and its `_sqlx_migrations` history table
-- before this file runs, so every Palisade object, the history included, lives in one schema
-- that this role owns.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'palisade_runtime') THEN
        RAISE EXCEPTION 'role palisade_runtime does not exist; run sql/bootstrap.sql first';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_roles
        WHERE rolname = 'palisade_runtime' AND (rolsuper OR rolbypassrls OR rolcanlogin)
    ) THEN
        RAISE EXCEPTION 'role palisade_runtime must be NOLOGIN, NOSUPERUSER and NOBYPASSRLS';
    END IF;
    IF (SELECT rolsuper FROM pg_catalog.pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION 'run migrations as the schema owner role from sql/bootstrap.sql, not as a superuser';
    END IF;
    IF pg_catalog.pg_has_role(current_user, 'palisade_runtime', 'MEMBER')
       OR pg_catalog.pg_has_role('palisade_runtime', current_user, 'MEMBER') THEN
        RAISE EXCEPTION 'the migration role and palisade_runtime must not be members of each other';
    END IF;
END
$$;

REVOKE ALL ON SCHEMA palisade FROM PUBLIC;
GRANT USAGE ON SCHEMA palisade TO palisade_runtime;
-- The runtime role reads the history to compare the schema with the binary. It cannot change it.
GRANT SELECT ON palisade._sqlx_migrations TO palisade_runtime;

-- The tenant scope of the current transaction, set by the server with
-- `set_config('palisade.tenant_ids', ..., true)` (SET LOCAL). Unset or empty means NULL, and
-- `tenant_id = ANY (NULL)` is never true, so a query without a scope sees no rows. A malformed
-- value fails the cast, so the query fails rather than matching anything.
CREATE FUNCTION palisade.current_tenant_ids() RETURNS uuid[]
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(pg_catalog.current_setting('palisade.tenant_ids', true), '')::pg_catalog.uuid[] $$;

-- Maintains created_at, updated_at and revision (optimistic concurrency, #185) on every table.
-- The client cannot choose them: inserts start at revision 1, and each update adds 1.
CREATE FUNCTION palisade.touch_row() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.created_at := now();
        NEW.updated_at := NEW.created_at;
        NEW.revision := 1;
    ELSE
        IF NEW.id IS DISTINCT FROM OLD.id THEN
            RAISE EXCEPTION '%.id cannot change', TG_TABLE_NAME USING ERRCODE = 'check_violation';
        END IF;
        NEW.created_at := OLD.created_at;
        NEW.updated_at := now();
        NEW.revision := OLD.revision + 1;
    END IF;
    RETURN NEW;
END
$$;

-- A row never moves to another tenant, even between two tenants in the caller's scope.
CREATE FUNCTION palisade.keep_tenant() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog
    AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        RAISE EXCEPTION '%.tenant_id cannot change', TG_TABLE_NAME USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
