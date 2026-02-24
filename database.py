from supabase import create_client
from config import SUPABASE_URL, SUPABASE_KEY

# Shared Supabase client — import this in app.py
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)