import os

# ── Supabase ──────────────────────────────────────────────
SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://kdmfxdwrbazarwtnivvu.supabase.co"
)
SUPABASE_KEY = os.environ.get(
    "SUPABASE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImtkbWZ4ZHdyYmF6YXJ3dG5pdnZ1Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MTkzMTgyMiwiZXhwIjoyMDg3NTA3ODIyfQ.v4OXrrX0P8X6VVHk0-PZXJ2tYw_TzO4ZzpygAAVCDAA"
)

# ── Flask ──────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey-ids-2026")

# ── Email (Gmail) ──────────────────────────────────────────
ADMIN_EMAIL     = os.environ.get("ADMIN_EMAIL",     "ivybarchebo40@gmail.com")
SENDER_EMAIL    = os.environ.get("SENDER_EMAIL",    "ivybarchebo40@gmail.com")
SENDER_PASSWORD = os.environ.get("SENDER_PASSWORD", "oqcfpzwewjccjtgt")