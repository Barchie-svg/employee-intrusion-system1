-- ============================================================
--  Intrusion Detection System — Supabase Schema
--  Run this entire script once in:
--  Supabase Dashboard → SQL Editor → New Query → Run
-- ============================================================

-- 1. Employees table
CREATE TABLE IF NOT EXISTS employees (
    id                SERIAL PRIMARY KEY,
    employee_number   VARCHAR(50)  UNIQUE NOT NULL,
    name              VARCHAR(100) NOT NULL,
    email             VARCHAR(100) NOT NULL,
    username          VARCHAR(50)  UNIQUE NOT NULL,
    password          VARCHAR(200) NOT NULL,
    status            VARCHAR(20)  NOT NULL DEFAULT 'Active',
    failed_attempts   INTEGER      NOT NULL DEFAULT 0,
    last_login        TIMESTAMP    NULL
);

-- 2. Admins table
CREATE TABLE IF NOT EXISTS admins (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(50)  UNIQUE NOT NULL,
    password  VARCHAR(200) NOT NULL
);

-- 3. Intrusion logs table
CREATE TABLE IF NOT EXISTS intrusion_logs (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(50),
    reason    VARCHAR(200),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);
