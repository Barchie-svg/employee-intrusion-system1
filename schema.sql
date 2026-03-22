-- ============================================================
--  Intrusion Detection System — Supabase Schema  (v2)
--
--  HOW TO USE:
--  1. Open Supabase Dashboard → SQL Editor → New Query
--  2. Paste this ENTIRE file and click Run
--  3. After it completes, run the SEED block at the bottom
-- ============================================================


-- ============================================================
--  STEP 1: Drop old tables (clean slate)
-- ============================================================
DROP TABLE IF EXISTS intrusion_logs CASCADE;
DROP TABLE IF EXISTS profiles CASCADE;
DROP TABLE IF EXISTS system_settings CASCADE;
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();


-- ============================================================
--  STEP 2: Create tables
-- ============================================================

-- System settings (dynamic config like email addresses)
CREATE TABLE system_settings (
    id          SERIAL PRIMARY KEY,
    key         VARCHAR(100) UNIQUE NOT NULL,
    value       TEXT NOT NULL,
    description TEXT
);

-- Profiles: stores both Employees and Admins.
-- NOTE: NO foreign key to auth.users — passwords are managed
--       by this application using bcrypt, not Supabase Auth.
CREATE TABLE profiles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) UNIQUE NOT NULL,
    role            VARCHAR(50)  NOT NULL DEFAULT 'Employee', -- 'Admin' or 'Employee'
    name            VARCHAR(100),
    employee_number VARCHAR(50)  UNIQUE,
    username        VARCHAR(50)  UNIQUE,
    password        TEXT,                   -- bcrypt hash stored here
    status          VARCHAR(20)  NOT NULL DEFAULT 'Active',
    failed_attempts INTEGER      NOT NULL DEFAULT 0,
    last_login      TIMESTAMP    WITH TIME ZONE,
    created_at      TIMESTAMP    WITH TIME ZONE DEFAULT NOW()
);

-- Intrusion logs
CREATE TABLE intrusion_logs (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(50),
    reason    VARCHAR(200),
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


-- ============================================================
--  STEP 3: Row-Level Security
--  The backend uses the service_role key which bypasses RLS,
--  so these policies simply prevent anonymous browser access.
-- ============================================================

ALTER TABLE system_settings  ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE intrusion_logs    ENABLE ROW LEVEL SECURITY;

-- Allow only the service_role (backend) — deny everything else
CREATE POLICY "Service role only on system_settings"
  ON system_settings FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role only on profiles"
  ON profiles FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role only on intrusion_logs"
  ON intrusion_logs FOR ALL USING (true) WITH CHECK (true);


-- ============================================================
--  STEP 4: SEED — Create the default Admin account
--  Password: admin123   (you can change this from the app later)
--
--  The bcrypt hash below = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
--  Generated externally because pgcrypto uses a different format.
--  The Python app uses bcrypt to verify it.
--
--  RUN THIS BLOCK AFTER THE TABLES ARE CREATED:
-- ============================================================

INSERT INTO profiles (id, name, email, username, password, role, status, failed_attempts)
VALUES (
    gen_random_uuid(),
    'System Admin',
    'admin@system.local',
    'admin',
    '$2b$12$LXMb6kM6hhXAb6YkYzK8aOHDhH.bEGkfZhkDDNdBZdJ.MbL25UR9i',
    'Admin',
    'Active',
    0
)
ON CONFLICT (username) DO UPDATE
SET password = EXCLUDED.password,
    role     = EXCLUDED.role,
    status   = EXCLUDED.status;
