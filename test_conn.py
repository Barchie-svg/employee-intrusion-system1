import sys
from database import supabase

def check_connection():
    try:
        # 1. Test profiles table
        print("--- Checking 'profiles' table ---")
        res = supabase.table('profiles').select('*').limit(1).execute()
        print("Connection Success!")
        if res.data:
            print(f"Columns found: {list(res.data[0].keys())}")
        else:
            print("Table 'profiles' exists but is empty.")
            
        # 2. Test intrusion_logs table
        print("\n--- Checking 'intrusion_logs' table ---")
        res_logs = supabase.table('intrusion_logs').select('*').limit(1).execute()
        print("Table 'intrusion_logs' accessible.")
        
        # 3. Test system_settings table
        print("\n--- Checking 'system_settings' table ---")
        res_settings = supabase.table('system_settings').select('*').limit(1).execute()
        print("Table 'system_settings' accessible.")
        
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    check_connection()
