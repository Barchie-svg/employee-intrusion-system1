-- ============================================================
--  PASTE THIS ENTIRE FILE INTO:
--  Supabase Dashboard → SQL Editor → New Query → RUN
--  (Safe to re-run — uses IF NOT EXISTS)
-- ============================================================

-- Add contact_email and status columns to companies table
ALTER TABLE companies ADD COLUMN IF NOT EXISTS contact_email VARCHAR(255);
ALTER TABLE companies ADD COLUMN IF NOT EXISTS status        VARCHAR(20) NOT NULL DEFAULT 'active';

-- Add company_id to intrusion logs and audit logs (for multi-tenant filtering)
ALTER TABLE intrusion_logs ADD COLUMN IF NOT EXISTS company_id UUID;
ALTER TABLE audit_logs     ADD COLUMN IF NOT EXISTS company_id UUID;

-- Add security columns to companies for Tenant Portal access
ALTER TABLE companies ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
ALTER TABLE companies ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE companies ADD COLUMN IF NOT EXISTS last_ip_address VARCHAR(45);
ALTER TABLE companies ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE;


-- Add allow_after_hours to employees (for per-employee bypass)
ALTER TABLE employees ADD COLUMN IF NOT EXISTS allow_after_hours BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS company_id UUID;

-- Ensure companies table exists
CREATE TABLE IF NOT EXISTS companies (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    api_key       VARCHAR(100) UNIQUE NOT NULL,
    contact_email VARCHAR(255),
    status        VARCHAR(20)  NOT NULL DEFAULT 'active',
    created_at    TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Ensure company_settings table exists
CREATE TABLE IF NOT EXISTS company_settings (
    id                      SERIAL PRIMARY KEY,
    company_id              UUID NOT NULL,
    working_hours_start     TIME NOT NULL DEFAULT '05:00:00',
    working_hours_end       TIME NOT NULL DEFAULT '23:00:00',
    max_failed_attempts     INTEGER NOT NULL DEFAULT 3,
    lockout_duration_minutes INTEGER NOT NULL DEFAULT 30
);

-- ADD MISSING COLUMNS IF THEY DON'T EXIST (for existing tables)
ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS working_hours_start      TIME    NOT NULL DEFAULT '05:00:00';
ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS working_hours_end        TIME    NOT NULL DEFAULT '23:00:00';
ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS max_failed_attempts      INTEGER NOT NULL DEFAULT 3;
ALTER TABLE company_settings ADD COLUMN IF NOT EXISTS lockout_duration_minutes INTEGER NOT NULL DEFAULT 30;

-- Grant permissions
GRANT ALL PRIVILEGES ON TABLE companies        TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE company_settings TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE employees        TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE intrusion_logs   TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE audit_logs       TO postgres, service_role, anon, authenticated;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role, anon, authenticated;

-- Disable Row Level Security (so anon key can access tables)
ALTER TABLE companies        DISABLE ROW LEVEL SECURITY;
ALTER TABLE company_settings DISABLE ROW LEVEL SECURITY;
ALTER TABLE employees        DISABLE ROW LEVEL SECURITY;
ALTER TABLE intrusion_logs   DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs       DISABLE ROW LEVEL SECURITY;

-- Verify
SELECT name, contact_email, status, created_at FROM companies ORDER BY created_at DESC LIMIT 10;
