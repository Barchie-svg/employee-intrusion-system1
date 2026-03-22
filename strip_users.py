import database
res = database.supabase.table('employees').select('id, username').execute()
fixed = 0
for emp in res.data:
    if emp['username']:
        stripped = emp['username'].strip()
        if emp['username'] != stripped:
            database.supabase.table('employees').update({'username': stripped}).eq('id', emp['id']).execute()
            fixed += 1
print(f"Usernames stripped: {fixed}")
