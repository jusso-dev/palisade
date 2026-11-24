-- The tenant and computer group tables, with row-level security (#127, ADR 0006).
--
-- Every tenant-owned table follows the same pattern, which `palisade-server migrate verify`
-- checks: a `tenant_id uuid NOT NULL` column, foreign keys between tenant-owned tables that
-- include `tenant_id`, ENABLE and FORCE ROW LEVEL SECURITY, and a policy keyed on
-- palisade.current_tenant_ids().

CREATE TYPE palisade.tenant_kind AS ENUM ('root', 'organisation', 'template');
CREATE TYPE palisade.tenant_status AS ENUM ('active', 'suspended');

CREATE TABLE palisade.tenant (
    id uuid NOT NULL,
    parent_id uuid,
    kind palisade.tenant_kind NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    status palisade.tenant_status NOT NULL DEFAULT 'active',
    settings jsonb NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT tenant_pkey PRIMARY KEY (id),
    CONSTRAINT tenant_parent_fkey FOREIGN KEY (parent_id) REFERENCES palisade.tenant (id),
    CONSTRAINT tenant_slug_key UNIQUE (slug),
    CONSTRAINT tenant_root_has_no_parent CHECK ((kind = 'root') = (parent_id IS NULL)),
    CONSTRAINT tenant_not_own_parent CHECK (parent_id <> id),
    CONSTRAINT tenant_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    CONSTRAINT tenant_display_name_length CHECK (char_length(display_name) BETWEEN 1 AND 200),
    CONSTRAINT tenant_settings_object CHECK (jsonb_typeof(settings) = 'object')
);

-- At most one root tenant.
CREATE UNIQUE INDEX tenant_single_root ON palisade.tenant ((true)) WHERE kind = 'root';
CREATE INDEX tenant_parent_idx ON palisade.tenant (parent_id);

CREATE TRIGGER tenant_touch BEFORE INSERT OR UPDATE ON palisade.tenant
    FOR EACH ROW EXECUTE FUNCTION palisade.touch_row();

-- A tenant row belongs to itself: its id is its tenant.
ALTER TABLE palisade.tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE palisade.tenant FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON palisade.tenant
    USING (id = ANY (palisade.current_tenant_ids()))
    WITH CHECK (id = ANY (palisade.current_tenant_ids()));

-- No DELETE: tenants are suspended, and their removal is a lifecycle job of its own.
GRANT SELECT, INSERT, UPDATE ON palisade.tenant TO palisade_runtime;

CREATE TYPE palisade.group_kind AS ENUM ('static', 'dynamic', 'directory');

CREATE TABLE palisade.computer_group (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    parent_id uuid,
    name text NOT NULL,
    kind palisade.group_kind NOT NULL DEFAULT 'static',
    built_in boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    revision bigint NOT NULL DEFAULT 1,
    CONSTRAINT computer_group_pkey PRIMARY KEY (id),
    -- The target of composite foreign keys from other tenant-owned tables.
    CONSTRAINT computer_group_tenant_id_id_key UNIQUE (tenant_id, id),
    CONSTRAINT computer_group_tenant_fkey FOREIGN KEY (tenant_id) REFERENCES palisade.tenant (id),
    -- The parent is always in the same tenant: the key includes tenant_id.
    CONSTRAINT computer_group_parent_fkey FOREIGN KEY (tenant_id, parent_id)
        REFERENCES palisade.computer_group (tenant_id, id),
    CONSTRAINT computer_group_not_own_parent CHECK (parent_id <> id),
    CONSTRAINT computer_group_name_length CHECK (char_length(name) BETWEEN 1 AND 200),
    CONSTRAINT computer_group_sibling_name_key UNIQUE NULLS NOT DISTINCT (tenant_id, parent_id, name)
);

CREATE INDEX computer_group_parent_idx ON palisade.computer_group (tenant_id, parent_id);

CREATE TRIGGER computer_group_touch BEFORE INSERT OR UPDATE ON palisade.computer_group
    FOR EACH ROW EXECUTE FUNCTION palisade.touch_row();
CREATE TRIGGER computer_group_keep_tenant BEFORE UPDATE ON palisade.computer_group
    FOR EACH ROW EXECUTE FUNCTION palisade.keep_tenant();

ALTER TABLE palisade.computer_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE palisade.computer_group FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON palisade.computer_group
    USING (tenant_id = ANY (palisade.current_tenant_ids()))
    WITH CHECK (tenant_id = ANY (palisade.current_tenant_ids()));

GRANT SELECT, INSERT, UPDATE, DELETE ON palisade.computer_group TO palisade_runtime;
