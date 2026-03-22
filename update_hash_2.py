import database
import bcrypt
# Generate a fresh correct hash for "admin123"
hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode()
# Update the admin account in the database
res = database.supabase.table('employees').update({'password': hashed}).eq('username', 'admin').execute()

print("Correctly generated hash: " + hashed)
print("Updated rows: " + str(len(res.data)))

# Test internally
val = bcrypt.checkpw(b'admin123', hashed.encode())
print("checkpw test passed:", val)
