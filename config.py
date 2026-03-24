import os
from dotenv import load_dotenv

load_dotenv()

# ── Supabase ──────────────────────────────────────────────
SUPABASE_URL = os.environ.get(
    "SUPABASE_URL",
    "https://xbyqiggasssjuuiwfaex.supabase.co"
)
SUPABASE_KEY = os.environ.get(
    "SUPABASE_KEY",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhieXFpZ2dhc3NzanV1aXdmYWV4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3MzgxNTkxNCwiZXhwIjoyMDg5MzkxOTE0fQ.uZvdRwo9BpOu7sJGT6-AX2Y0AsVFhJhBHlNiLK9-pro"
)

# ── Flask ──────────────────────────────────────────────────
SECRET_KEY = os.environ.get("SECRET_KEY", "supersecretkey-ids-2026")

# Hardcoded emails have been removed. System administrators can update 
# these dynamically via the database ('system_settings' table) 
# and the Admin Dashboard.