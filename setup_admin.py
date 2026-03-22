"""
setup_admin.py
==============
Run this script ONCE to generate the SQL you need to paste in Supabase.
Usage:  python setup_admin.py
Then copy the printed SQL and run it in:
Supabase Dashboard → SQL Editor → New Query → Paste → Run
"""

import bcrypt

# Change this password if you want something different
ADMIN_USERNAME = "admin"
ADMIN_EMAIL    = "admin@system.local"
ADMIN_PASSWORD = "admin123"

print("\n" + "="*60)
print("  SUPABASE SETUP — Copy and run the SQL below")
print("="*60)

# Generate a fresh bcrypt hash
hashed = bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode()

print("""
-- ─────────────────────────────────────────────────────────
-- STEP 1: Fix the profiles table
--         (Remove FK to auth.users, add password column)
-- ─────────────────────────────────────────────────────────

-- Drop the foreign key constraint (if it exists)
ALTER TABLE profiles
  DROP CONSTRAINT IF EXISTS profiles_id_fkey;

-- Add the password column (if it doesn't exist)
ALTER TABLE profiles
  ADD COLUMN IF NOT EXISTS password TEXT;

-- Make 'id' auto-generate instead of requiring auth.users
ALTER TABLE profiles
  ALTER COLUMN id SET DEFAULT gen_random_uuid();

-- ─────────────────────────────────────────────────────────
-- STEP 2: Insert (or update) the admin account
-- ─────────────────────────────────────────────────────────
""")

print(f"""INSERT INTO profiles (name, email, username, password, role, status, failed_attempts)
VALUES (
  'System Admin',
  '{ADMIN_EMAIL}',
  '{ADMIN_USERNAME}',
  '{hashed}',
  'Admin',
  'Active',
  0
)
ON CONFLICT (username) DO UPDATE
  SET password = EXCLUDED.password,
      role     = 'Admin',
      status   = 'Active';
""")

print("="*60)
print(f"  After running the SQL, login with:")
print(f"  Email or Username : {ADMIN_USERNAME}")
print(f"  Password          : {ADMIN_PASSWORD}")
print("="*60 + "\n")
