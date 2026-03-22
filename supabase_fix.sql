-- ============================================================
--  PASTE THIS ENTIRE FILE INTO:
--  Supabase Dashboard → SQL Editor → New Query → RUN
-- ============================================================

-- STEP 1: Create the employees table (standalone, no links to auth.users)
CREATE TABLE IF NOT EXISTS employees (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(100),
    email           VARCHAR(255) UNIQUE NOT NULL,
    username        VARCHAR(50)  UNIQUE,
    employee_number VARCHAR(50)  UNIQUE,
    password        TEXT,
    role            VARCHAR(50)  NOT NULL DEFAULT 'Employee',
    status          VARCHAR(20)  NOT NULL DEFAULT 'Active',
    failed_attempts INTEGER      NOT NULL DEFAULT 0,
    last_login      TIMESTAMP WITH TIME ZONE,
    last_ip_address VARCHAR(45),
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ADD COLUMNS IF THEY DON'T EXIST (for existing tables)
ALTER TABLE employees ADD COLUMN IF NOT EXISTS last_ip_address VARCHAR(45);
ALTER TABLE employees ADD COLUMN IF NOT EXISTS last_login      TIMESTAMP WITH TIME ZONE;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE employees ADD COLUMN IF NOT EXISTS status          VARCHAR(20) NOT NULL DEFAULT 'Active';
ALTER TABLE employees ADD COLUMN IF NOT EXISTS role            VARCHAR(50) NOT NULL DEFAULT 'Employee';
ALTER TABLE employees ADD COLUMN IF NOT EXISTS employee_number VARCHAR(50);
ALTER TABLE employees ADD COLUMN IF NOT EXISTS username        VARCHAR(50);

-- STEP 2: Create intrusion_logs table
CREATE TABLE IF NOT EXISTS intrusion_logs (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(50),
    reason      VARCHAR(200),
    ip_address  VARCHAR(45),
    device_info TEXT,
    timestamp   TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- ADD COLUMNS IF THEY DON'T EXIST (for existing tables)
ALTER TABLE intrusion_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45);
ALTER TABLE intrusion_logs ADD COLUMN IF NOT EXISTS device_info TEXT;

-- STEP 2.5: Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id             SERIAL PRIMARY KEY,
    admin_username VARCHAR(50),
    action         VARCHAR(100),
    target         VARCHAR(100),
    ip_address     VARCHAR(45),
    timestamp      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- STEP 3: Create system_settings table
CREATE TABLE IF NOT EXISTS system_settings (
    id          SERIAL PRIMARY KEY,
    key         VARCHAR(100) UNIQUE NOT NULL,
    value       TEXT NOT NULL,
    description TEXT
);

-- STEP 3.5: Create password_reset_tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id         SERIAL PRIMARY KEY,
    user_id    UUID NOT NULL,
    token      VARCHAR(100) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- STEP 4: Grant full access to all Supabase roles
GRANT ALL PRIVILEGES ON TABLE employees              TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE intrusion_logs         TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE system_settings        TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE audit_logs             TO postgres, service_role, anon, authenticated;
GRANT ALL PRIVILEGES ON TABLE password_reset_tokens  TO postgres, service_role, anon, authenticated;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO postgres, service_role, anon, authenticated;

-- STEP 5: Disable Row Level Security
ALTER TABLE employees               DISABLE ROW LEVEL SECURITY;
ALTER TABLE intrusion_logs          DISABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings         DISABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs              DISABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens   DISABLE ROW LEVEL SECURITY;

-- STEP 6: Insert the admin account
--         Username: admin   |   Password: admin123
INSERT INTO employees (name, email, username, password, role, status, failed_attempts)
VALUES (
  'System Admin',
  'admin@system.local',
  'admin',
  '$2b$12$tit9ftIQLnsISmCnyhPM1uATLjKSE8aU2GGXAEfNFtCkXITNLNMa.',
  'Admin',
  'Active',
  0
)
ON CONFLICT (username) DO UPDATE
  SET role            = 'Admin',
      status          = 'Active',
      failed_attempts = 0,
      name            = EXCLUDED.name,
      email           = EXCLUDED.email;
  -- NOTE: password is intentionally NOT updated on conflict.
  -- To reset the admin password, use setup_admin.py instead.

-- STEP 7: Verify
SELECT username, email, role, status,
       (password IS NOT NULL) AS has_password
FROM employees
WHERE role = 'Admin';
