import mysql.connector
import hashlib

# Database connection
config = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '',  # Your MySQL password
    'database': 'car_troubleshooting'
}

def fix_admin_password():
    try:
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        
        # Get current admin password
        cursor.execute("SELECT password_hash FROM users WHERE username = 'admin'")
        result = cursor.fetchone()
        
        if result:
            current_hash = result[0]
            print(f"Current password hash: {current_hash}")
        
        # Hash the password
        password = "admin123"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Update the password
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE username = 'admin'",
            (password_hash,)
        )
        
        conn.commit()
        print(f"✅ Admin password updated!")
        print(f"New hash: {password_hash}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":import mysql.connector
import hashlib

# Database connection
config = {
    'host': 'localhost',
    'port': 3306,
    'user': 'root',
    'password': '',  # Your MySQL password
    'database': 'car_troubleshooting'
}

def fix_admin_password():
    try:
        conn = mysql.connector.connect(**config)
        cursor = conn.cursor()
        
        # Get current admin password
        cursor.execute("SELECT password_hash FROM users WHERE username = 'admin'")
        result = cursor.fetchone()
        
        if result:
            current_hash = result[0]
            print(f"Current password hash: {current_hash}")
        
        # Hash the password
        password = "admin123"
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Update the password
        cursor.execute(
            "UPDATE users SET password_hash = %s WHERE username = 'admin'",
            (password_hash,)
        )
        
        conn.commit()
        print(f"✅ Admin password updated!")
        print(f"New hash: {password_hash}")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    fix_admin_password()
    fix_admin_password()