-- ============================================================
--  Intrusion Detection System — Supabase Schema  (v3 SaaS)
--
--  HOW TO USE:
--  1. Open Supabase Dashboard → SQL Editor → New Query
--  2. Paste this ENTIRE file and click Run
--  3. After it completes, run the SEED block at the bottom
-- ============================================================


-- ============================================================
--  STEP 1: Drop old tables (clean slate for SaaS Upgrade)
-- ============================================================
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS intrusion_logs CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS employees CASCADE;
DROP TABLE IF EXISTS company_settings CASCADE;
DROP TABLE IF EXISTS companies CASCADE;
DROP TABLE IF EXISTS system_settings CASCADE;
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();


-- ============================================================
--  STEP 2: Create tables
-- ============================================================

-- 1. System Settings (Global Config like Master Admin Email)
CREATE TABLE system_settings (
    id          SERIAL PRIMARY KEY,
    key         VARCHAR(100) UNIQUE NOT NULL,
    value       TEXT NOT NULL,
    description TEXT
);

-- 2. Companies (Multi-Tenant SaaS Clients)
CREATE TABLE companies (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                VARCHAR(150) UNIQUE NOT NULL,
    api_key             VARCHAR(100) UNIQUE NOT NULL,
    subscription_status VARCHAR(50)  NOT NULL DEFAULT 'Active',
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 3. Company Settings (Working Hours, Limits per Client)
CREATE TABLE company_settings (
    id                      SERIAL PRIMARY KEY,
    company_id              UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    working_hours_start     TIME DEFAULT '05:00:00',
    working_hours_end       TIME DEFAULT '23:00:00',
    max_failed_attempts     INTEGER DEFAULT 3,
    UNIQUE(company_id)
);

-- 4. Employees / Users (Linked to Companies)
CREATE TABLE employees (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID REFERENCES companies(id) ON DELETE CASCADE, 
    email           VARCHAR(255) UNIQUE NOT NULL,
    role            VARCHAR(50)  NOT NULL DEFAULT 'Employee', -- 'SuperAdmin', 'CompanyAdmin', 'Employee'
    name            VARCHAR(100),
    employee_number VARCHAR(50)  UNIQUE,
    username        VARCHAR(50)  UNIQUE,
    password        TEXT,                   -- bcrypt hash
    status          VARCHAR(20)  NOT NULL DEFAULT 'Active',
    failed_attempts INTEGER      NOT NULL DEFAULT 0,
    last_login      TIMESTAMP    WITH TIME ZONE,
    last_ip_address VARCHAR(50),
    created_at      TIMESTAMP    WITH TIME ZONE DEFAULT NOW()
);

-- 5. Intrusion Logs (Linked to Companies)
CREATE TABLE intrusion_logs (
    id          SERIAL PRIMARY KEY,
    company_id  UUID REFERENCES companies(id) ON DELETE CASCADE,
    username    VARCHAR(100),
    reason      VARCHAR(255),
    ip_address  VARCHAR(50),
    device_info TEXT,
    timestamp   TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 6. Audit Logs (Linked to Companies)
CREATE TABLE audit_logs (
    id              SERIAL PRIMARY KEY,
    company_id      UUID REFERENCES companies(id) ON DELETE CASCADE,
    admin_username  VARCHAR(100),
    action          VARCHAR(255),
    target          VARCHAR(255),
    ip_address      VARCHAR(50),
    timestamp       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 7. Password Reset Tokens
CREATE TABLE password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    user_id     UUID REFERENCES employees(id) ON DELETE CASCADE,
    token       VARCHAR(64) UNIQUE NOT NULL,
    expires_at  TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


-- ============================================================
--  STEP 3: Row-Level Security
--  The backend uses the service_role key which bypasses RLS.
-- ============================================================

ALTER TABLE system_settings  ENABLE ROW LEVEL SECURITY;
ALTER TABLE companies        ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE employees        ENABLE ROW LEVEL SECURITY;
ALTER TABLE intrusion_logs   ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs       ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role only" ON system_settings  FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role only" ON companies        FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role only" ON company_settings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role only" ON employees        FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role only" ON intrusion_logs   FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role only" ON audit_logs       FOR ALL USING (true) WITH CHECK (true);


-- ============================================================
--  STEP 4: SEED — Create the System SuperAdmin & Default Company
-- ============================================================

-- 1. Create a Default Company with a dummy API KEY
INSERT INTO companies (id, name, api_key) 
VALUES ('00000000-0000-0000-0000-000000000000', 'Local Host Corp', 'sk_test_12345abcde');

-- 2. Set default settings for the company
INSERT INTO company_settings (company_id, working_hours_start, working_hours_end, max_failed_attempts)
VALUES ('00000000-0000-0000-0000-000000000000', '05:00:00', '23:00:00', 3);

-- 3. Create SuperAdmin
INSERT INTO employees (id, company_id, name, email, username, password, role, status, failed_attempts)
VALUES (
    gen_random_uuid(),
    NULL, -- SuperAdmins don't belong to a single company
    'System Admin',
    'admin@system.local',
    'admin',
    '$2b$12$LXMb6kM6hhXAb6YkYzK8aOHDhH.bEGkfZhkDDNdBZdJ.MbL25UR9i', -- admin123
    'SuperAdmin',
    'Active',
    0
)
ON CONFLICT (username) DO UPDATE
SET password = EXCLUDED.password, role = EXCLUDED.role, status = EXCLUDED.status;
