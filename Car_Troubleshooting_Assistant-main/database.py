# database.py Car_Troubleshooting Assistant - MySQL Version
import os
import json
from datetime import date, datetime
import mysql.connector
from mysql.connector import pooling, Error
from dotenv import load_dotenv
import base64

# Load environment variables
load_dotenv()

# MySQL Connection Configuration
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', '') or None,
    'database': os.getenv('MYSQL_DATABASE', 'car_troubleshooting'),
    'pool_name': 'car_troubleshooting_pool',
    'pool_size': 5,
    'pool_reset_session': True
}

# Remove empty password from config if it's None
if MYSQL_CONFIG['password'] is None:
    MYSQL_CONFIG.pop('password')

# Create connection pool
connection_pool = None

def init_connection_pool():
    """Initialize MySQL connection pool"""
    global connection_pool
    try:
        # Create config without pool settings for testing
        test_config = MYSQL_CONFIG.copy()
        if 'pool_name' in test_config:
            del test_config['pool_name']
            del test_config['pool_size']
            del test_config['pool_reset_session']
        
        # Test connection first
        test_conn = mysql.connector.connect(**test_config)
        test_conn.close()
        
        # Now create pool
        connection_pool = mysql.connector.pooling.MySQLConnectionPool(**MYSQL_CONFIG)
    except Error:
        pass
        
def check_username_exists(username):
    """Check if a username already exists"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        count = cursor.fetchone()[0]
        return count > 0
    finally:
        cursor.close()
        conn.close()        

def get_db_connection():
    """Get a database connection from pool or create new one"""
    if connection_pool is None:
        init_connection_pool()
    
    try:
        # Try to get from pool
        if connection_pool:
            conn = connection_pool.get_connection()
            return conn
        else:
            # Fallback to direct connection
            config = MYSQL_CONFIG.copy()
            if 'pool_name' in config:
                del config['pool_name']
                del config['pool_size']
                del config['pool_reset_session']
            return mysql.connector.connect(**config)
    except Error:
        # Try direct connection as last resort
        try:
            config = MYSQL_CONFIG.copy()
            if 'pool_name' in config:
                del config['pool_name']
                del config['pool_size']
                del config['pool_reset_session']
            return mysql.connector.connect(**config)
        except Error:
            raise ConnectionError("Cannot connect to MySQL")

def create_tables():
    """Create required tables with role support"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Users table for authentication and roles
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                role ENUM('admin', 'expert', 'user') DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                profile_picture LONGBLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            )
        ''')
        
        # Facts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS facts (
                id VARCHAR(50) PRIMARY KEY,
                description TEXT NOT NULL,
                value BOOLEAN DEFAULT FALSE,
                tags JSON,
                category VARCHAR(100) DEFAULT 'uncategorized',
                display_order INT DEFAULT 0,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # Rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id VARCHAR(50) PRIMARY KEY,
                conditions JSON NOT NULL,
                conclusion VARCHAR(100) NOT NULL,
                certainty DECIMAL(4,3) DEFAULT 1.000,
                explanation TEXT,
                recommendation TEXT,
                display_order INT DEFAULT 0,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # Taxonomy table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS taxonomy (
                id INT PRIMARY KEY AUTO_INCREMENT,
                child VARCHAR(100) NOT NULL,
                parent VARCHAR(100) NOT NULL,
                created_by INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,  -- ADD THIS
                UNIQUE KEY unique_child (child),
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # History table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS history (
                id INT PRIMARY KEY AUTO_INCREMENT,
                timestamp VARCHAR(50),
                observations JSON,
                expanded_obs JSON,
                results JSON,
                user_id INT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        # Audit log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INT PRIMARY KEY AUTO_INCREMENT,
                user_id INT,
                action VARCHAR(50) NOT NULL,
                table_name VARCHAR(50),
                record_id VARCHAR(100),
                old_value JSON,
                new_value JSON,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            )
        ''')
        
        conn.commit()
        
        # Create default admin user if not exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cursor.fetchone()[0] == 0:
            import hashlib
            default_password = "admin123"
            password_hash = hashlib.sha256(default_password.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO users (username, password_hash, email, role)
                VALUES (%s, %s, %s, %s)
            ''', ('admin', password_hash, 'admin@example.com', 'admin'))
            conn.commit()
            
    except Error as e:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

# ============================================================
#                      USER MANAGEMENT
# ============================================================
def update_user_profile(user_id, username=None, email=None, profile_picture=None):
    """Update user profile information"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        updates = []
        params = []
        
        if username:
            updates.append("username = %s")
            params.append(username)
        
        if email:
            updates.append("email = %s")
            params.append(email)
        
        # Handle profile picture
        if profile_picture is not None:
            updates.append("profile_picture = %s")
            params.append(profile_picture)
        else:
            updates.append("profile_picture = NULL")
        
        if updates:
            params.append(user_id)
            sql = f"UPDATE users SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s"
            cursor.execute(sql, params)
            conn.commit()
            return True
        
        return False
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to update profile: {e}")
    finally:
        cursor.close()
        conn.close()

def get_user_profile_picture(user_id):
    """Get user's profile picture"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT profile_picture FROM users WHERE id = %s", (user_id,))
        result = cursor.fetchone()
        return result['profile_picture'] if result and result['profile_picture'] else None
    except Error as e:
        raise Exception(f"Failed to get profile picture: {e}")
    finally:
        cursor.close()
        conn.close()

def save_profile_picture(user_id, file_data, filename):
    """Save profile picture to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET profile_picture = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", 
                      (file_data, user_id))
        conn.commit()
        
        # Also save to static folder
        import os
        from PIL import Image
        import io
        
        upload_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads', 'profiles')
        os.makedirs(upload_dir, exist_ok=True)
        
        file_path = os.path.join(upload_dir, f"user_{user_id}_{filename}")
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # Create thumbnail
        try:
            img = Image.open(io.BytesIO(file_data))
            img.thumbnail((200, 200))
            thumb_path = os.path.join(upload_dir, f"user_{user_id}_thumb_{filename}")
            img.save(thumb_path)
        except:
            pass
        
        return file_path
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to save profile picture: {e}")
    finally:
        cursor.close()
        conn.close()

def get_all_users():
    """Get all users (admin only)"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT id, username, email, role, is_active, created_at
            FROM users 
            ORDER BY id ASC
        ''')
        return cursor.fetchall()
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()

def create_user(username, password, email=None, role='user'):
    """Create a new user"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        import hashlib
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, email, role)
            VALUES (%s, %s, %s, %s)
        ''', (username, password_hash, email, role))
        
        conn.commit()
        return cursor.lastrowid
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to create user: {e}")
    finally:
        cursor.close()
        conn.close()

def authenticate_user(username, password):
    """Authenticate user and return user data"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        import hashlib
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        cursor.execute('''
            SELECT id, username, email, role, is_active 
            FROM users 
            WHERE username = %s AND password_hash = %s AND is_active = TRUE
        ''', (username, password_hash))
        
        return cursor.fetchone()
    except Error as e:
        raise Exception(f"Authentication failed: {e}")
    finally:
        cursor.close()
        conn.close()

def get_user(user_id):
    """Get user by ID"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute('''
            SELECT id, username, email, role, is_active, 
                   profile_picture, created_at, updated_at
            FROM users 
            WHERE id = %s
        ''', (user_id,))
        
        user = cursor.fetchone()
        
        if user:
            profile_pic = user.get('profile_picture')
            if profile_pic:
                try:
                    if isinstance(profile_pic, bytes):
                        user['profile_picture'] = base64.b64encode(profile_pic).decode('utf-8')
                    elif isinstance(profile_pic, str):
                        try:
                            base64.b64decode(profile_pic)
                            user['profile_picture'] = profile_pic
                        except:
                            user['profile_picture'] = base64.b64encode(profile_pic.encode()).decode('utf-8')
                    else:
                        user['profile_picture'] = base64.b64encode(str(profile_pic).encode()).decode('utf-8')
                except:
                    user['profile_picture'] = None
            else:
                user['profile_picture'] = None
        
        return user
    except Error as e:
        raise Exception(f"Failed to get user: {e}")
    finally:
        cursor.close()
        conn.close()

def update_user_role(user_id, role):
    """Update user role"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            UPDATE users 
            SET role = %s 
            WHERE id = %s
        ''', (role, user_id))
        
        conn.commit()
        return cursor.rowcount > 0
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to update user role: {e}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
#                      FACTS FUNCTIONS
# ============================================================
def get_all_facts(user_id=None):
    """Get all facts, optionally filtered by user"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if user_id:
            cursor.execute('''
                SELECT f.id, f.description, f.value, f.tags, f.category
                FROM facts f
                WHERE f.created_by = %s
                ORDER BY f.display_order, f.id
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT f.id, f.description, f.value, f.tags, f.category
                FROM facts f
                ORDER BY f.display_order, f.id
            ''')
        
        rows = cursor.fetchall()
        facts = []
        
        for row in rows:
            fact = {
                "id": row["id"],
                "description": row["description"],
                "value": bool(row["value"]) if row["value"] is not None else False,
                "category": row["category"] or "uncategorized"
            }
            
            if row["tags"]:
                try:
                    fact["tags"] = json.loads(row["tags"])
                except:
                    fact["tags"] = []
            else:
                fact["tags"] = []
            
            facts.append(fact)
        
        # Natural sorting
        def natural_sort_key(fact):
            fact_id = fact["id"]
            if fact_id.startswith('f') and fact_id[1:].isdigit():
                return int(fact_id[1:])
            return float('inf')
        
        facts.sort(key=natural_sort_key)
        return facts
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()

def get_fact(fid):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id, description, value, tags, category FROM facts WHERE id = %s", (fid,))
        row = cursor.fetchone()
        
        if not row:
            return None
            
        fact = {
            "id": row["id"],
            "description": row["description"],
            "value": bool(row["value"]) if row["value"] is not None else False,
            "category": row["category"] or "uncategorized"
        }
        
        if row["tags"]:
            try:
                fact["tags"] = json.loads(row["tags"])
            except:
                fact["tags"] = []
        else:
            fact["tags"] = []
            
        return fact
    except Error:
        return None
    finally:
        cursor.close()
        conn.close()

def save_fact(fact, user_id=None):
    """Insert or update a fact with user tracking"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        tags_json = json.dumps(fact.get("tags", []))
        
        cursor.execute('''
            INSERT INTO facts (id, description, value, tags, category, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                description = VALUES(description),
                value = VALUES(value),
                tags = VALUES(tags),
                category = VALUES(category),
                updated_at = CURRENT_TIMESTAMP
        ''', (
            fact["id"],
            fact.get("description", ""),
            1 if fact.get("value", False) else 0,
            tags_json,
            fact.get("category", "uncategorized"),
            user_id
        ))
        
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to save fact: {e}")
    finally:
        cursor.close()
        conn.close()

def delete_fact(fid, user_id=None):
    """Delete fact with audit logging"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM facts WHERE id = %s", (fid,))
        old_value = cursor.fetchone()
        
        cursor.execute("DELETE FROM facts WHERE id = %s", (fid,))
        conn.commit()
        
        if old_value and user_id:
            log_audit(user_id, 'DELETE', 'facts', fid, old_value, None)
            
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to delete fact: {e}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
#                      RULES FUNCTIONS
# ============================================================
def get_all_rules(user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if user_id:
            cursor.execute('''
                SELECT r.id, r.conditions, r.conclusion, r.certainty, 
                       r.explanation, r.recommendation
                FROM rules r
                WHERE r.created_by = %s
                ORDER BY r.display_order, r.id
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT r.id, r.conditions, r.conclusion, r.certainty, 
                       r.explanation, r.recommendation
                FROM rules r
                ORDER BY r.display_order, r.id
            ''')
        
        rows = cursor.fetchall()
        rules = []
        
        for row in rows:
            rule = {
                "id": row["id"],
                "conclusion": row["conclusion"],
                "certainty": float(row["certainty"]) if row["certainty"] is not None else 1.0,
                "explain": row["explanation"] or "",
                "recommendation": row["recommendation"] or ""
            }
            
            if row["conditions"]:
                try:
                    rule["conditions"] = json.loads(row["conditions"])
                except:
                    rule["conditions"] = []
            else:
                rule["conditions"] = []
            
            rules.append(rule)
        
        # Natural sorting
        def natural_sort_key(rule):
            rule_id = rule["id"]
            if rule_id.startswith('r') and rule_id[1:].isdigit():
                return int(rule_id[1:])
            return float('inf')
        
        rules.sort(key=natural_sort_key)
        return rules
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()
def save_rule(rule, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ---------- Conditions ----------
        conditions_json = json.dumps(rule.get("conditions", []))

        # ---------- Explanation ----------
        explanation = rule.get("explain") or rule.get("explanation") or ""

        # ---------- Certainty handling ----------
        # Check if certainty is already a float (from app.py conversion)
        certainty = rule.get("certainty", 0.8)
        
        if isinstance(certainty, str):
            try:
                certainty = float(certainty)
                # If it's a string that might be a percentage
                if certainty > 1:
                    certainty = certainty / 100.0
            except (ValueError, TypeError):
                certainty = 0.8
        
        # Ensure it's a float and clamp between 0 and 1
        certainty = float(certainty)
        certainty = max(0.0, min(1.0, certainty))
        
        # Round to 3 decimal places for database
        certainty = round(certainty, 3)

        # ---------- SQL ----------
        cursor.execute('''
            INSERT INTO rules (
                id, conditions, conclusion, certainty,
                explanation, recommendation, created_by
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                conditions = VALUES(conditions),
                conclusion = VALUES(conclusion),
                certainty = VALUES(certainty),
                explanation = VALUES(explanation),
                recommendation = VALUES(recommendation),
                updated_at = CURRENT_TIMESTAMP
        ''', (
            rule["id"],
            conditions_json,
            rule.get("conclusion", ""),
            certainty,
            explanation,
            rule.get("recommendation", ""),
            user_id
        ))

        conn.commit()
        return True

    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to save rule: {e}")

    finally:
        cursor.close()
        conn.close()

def delete_rule(rid, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT * FROM rules WHERE id = %s", (rid,))
        old_value = cursor.fetchone()
        
        cursor.execute("DELETE FROM rules WHERE id = %s", (rid,))
        conn.commit()
        
        if old_value and user_id:
            log_audit(user_id, 'DELETE', 'rules', rid, old_value, None)
            
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to delete rule: {e}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
#                    TAXONOMY FUNCTIONS
# ============================================================
def get_taxonomy():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT child, parent FROM taxonomy")
        rows = cursor.fetchall()
        
        parent_map = {}
        for row in rows:
            parent_map[row["child"]] = row["parent"]
        
        return {"parent": parent_map}
    except Error:
        return {"parent": {}}
    finally:
        cursor.close()
        conn.close()

def save_taxonomy(taxonomy, user_id=None):
    parent_map = taxonomy.get("parent", {}) if isinstance(taxonomy, dict) else {}
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM taxonomy")
        
        for child, parent in parent_map.items():
            cursor.execute('''
                INSERT INTO taxonomy (child, parent, created_by)
                VALUES (%s, %s, %s)
            ''', (child, parent, user_id))
        
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to save taxonomy: {e}")
    finally:
        cursor.close()
        conn.close()

def update_taxonomy_relationship(child, parent, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if the column exists
        cursor.execute("SHOW COLUMNS FROM taxonomy LIKE 'updated_at'")
        has_updated_at = cursor.fetchone() is not None
        
        if has_updated_at:
            cursor.execute('''
                INSERT INTO taxonomy (child, parent, created_by)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    parent = VALUES(parent),
                    updated_at = CURRENT_TIMESTAMP
            ''', (child, parent, user_id))
        else:
            # Fallback for old schema
            cursor.execute('''
                INSERT INTO taxonomy (child, parent, created_by)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    parent = VALUES(parent)
            ''', (child, parent, user_id))
        
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to update taxonomy: {e}")
    finally:
        cursor.close()
        conn.close()

def delete_taxonomy_relationship(child, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM taxonomy WHERE child = %s", (child,))
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to delete taxonomy relationship: {e}")
    finally:
        cursor.close()
        conn.close()

# ============================================================
#                    HISTORY FUNCTIONS
# ============================================================
def get_history(user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if user_id:
            cursor.execute('''
                SELECT h.*, u.username
                FROM history h
                LEFT JOIN users u ON h.user_id = u.id
                WHERE h.user_id = %s
                ORDER BY h.id ASC
            ''', (user_id,))
        else:
            cursor.execute('''
                SELECT h.*, u.username
                FROM history h
                LEFT JOIN users u ON h.user_id = u.id
                ORDER BY h.id ASC
            ''')
        
        rows = cursor.fetchall()
        items = []
        
        for row in rows:
            item = {
                "id": row["id"],
                "timestamp": row["timestamp"],
                "username": row["username"]
            }
            
            for field in ["observations", "expanded_obs", "results"]:
                if row[field]:
                    try:
                        item[field] = json.loads(row[field])
                    except:
                        item[field] = {}
                else:
                    item[field] = {}
            
            items.append(item)
        return items
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()

#  update to day 18 january 2026
def save_history_item(item, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO history (timestamp, observations, expanded_obs, results, user_id)
            VALUES (%s, %s, %s, %s, %s)
        ''', (
            item.get("timestamp", datetime.now().isoformat()),
            json.dumps(item.get("observations", {})),
            json.dumps(item.get("expanded_obs", {})),
            json.dumps(item.get("results", [])),
            user_id
        ))
        
        conn.commit()
        
        # Log audit for history creation
        if user_id:
            log_audit(
                user_id=user_id,
                action='CREATE',
                table_name='history',
                record_id=cursor.lastrowid,
                old_value=None,
                new_value={'timestamp': item.get("timestamp"), 'action': 'inference'},
                ip_address=None,
                user_agent=None
            )
            
        return cursor.lastrowid
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to save history: {e}")
    finally:
        cursor.close()
        conn.close()

# update to day 18 january 2026
def delete_history_item(hid, user_id=None):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        # Get history item before deletion for audit logging
        cursor.execute("SELECT * FROM history WHERE id = %s", (hid,))
        old_value = cursor.fetchone()
        
        cursor.execute("DELETE FROM history WHERE id = %s", (hid,))
        conn.commit()
        
        # Log audit - DELETE action
        if old_value and user_id:
            # Clean old_value before logging
            cleaned_old_value = dict(old_value)
            for key, value in cleaned_old_value.items():
                if isinstance(value, datetime):
                    cleaned_old_value[key] = value.isoformat()
                elif isinstance(value, date):
                    cleaned_old_value[key] = value.isoformat()
            
            log_audit(
                user_id=user_id,
                action='DELETE',
                table_name='history',
                record_id=hid,
                old_value=cleaned_old_value,
                new_value=None,
                ip_address=None,
                user_agent=None
            )
            
        return True
    except Error as e:
        conn.rollback()
        raise Exception(f"Failed to delete history: {e}")
    finally:
        cursor.close()
        conn.close()
# ============================================================
#                    AUDIT LOG FUNCTIONS
# ============================================================
# update to day 18 january 2026
def log_audit(user_id, action, table_name, record_id, old_value, new_value, ip_address=None, user_agent=None):
    """Log user actions for auditing"""
    
    def serialize_value(value):
        """Helper function to serialize values with datetime support"""
        if value is None:
            return None
        
        if isinstance(value, dict):
            # Recursively process dictionary
            result = {}
            for key, val in value.items():
                result[key] = serialize_value(val)
            return result
        elif isinstance(value, list):
            # Recursively process list
            return [serialize_value(item) for item in value]
        elif isinstance(value, datetime):
            # Convert datetime to ISO format string
            return value.isoformat()
        elif isinstance(value, date):
            # Convert date to ISO format string
            return value.isoformat()
        elif hasattr(value, 'isoformat'):
            # Handle any other objects with isoformat method
            try:
                return value.isoformat()
            except:
                return str(value)
        elif isinstance(value, (int, float, bool, str)):
            # Basic types that are JSON serializable
            return value
        else:
            # Fallback to string representation
            return str(value)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Serialize old_value and new_value
        serialized_old = json.dumps(serialize_value(old_value)) if old_value else None
        serialized_new = json.dumps(serialize_value(new_value)) if new_value else None
        
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, table_name, record_id, old_value, new_value, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ''', (
            user_id,
            action,
            table_name,
            str(record_id),
            serialized_old,
            serialized_new,
            ip_address,
            user_agent
        ))
        
        conn.commit()
        return True
    except Error as e:
        conn.rollback()
        # Log error but don't crash
        print(f"Audit logging failed: {e}")
        return False
    finally:
        cursor.close()
        conn.close()
        
def get_audit_logs(user_id=None, limit=100):
    """Get audit logs"""
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    try:
        if user_id:
            cursor.execute('''
                SELECT al.*, u.username
                FROM audit_log al
                LEFT JOIN users u ON al.user_id = u.id
                WHERE al.user_id = %s
                ORDER BY al.created_at DESC
                LIMIT %s
            ''', (user_id, limit))
        else:
            cursor.execute('''
                SELECT al.*, u.username
                FROM audit_log al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.created_at DESC
                LIMIT %s
            ''', (limit,))
        
        return cursor.fetchall()
    except Error:
        return []
    finally:
        cursor.close()
        conn.close()
# ============================================================
#                    INITIALIZATION
# ============================================================
def init_database():
    """Initialize database and tables"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # First ensure the database exists
            db_config = MYSQL_CONFIG.copy()
            database_name = db_config.pop('database', 'car_troubleshooting')
            
            # Remove pool settings for initial connection
            for key in ['pool_name', 'pool_size', 'pool_reset_session']:
                if key in db_config:
                    del db_config[key]
            
            # Connect without database specified
            try:
                temp_conn = mysql.connector.connect(**db_config)
                temp_cursor = temp_conn.cursor()
                
                temp_cursor.execute(f"SHOW DATABASES LIKE '{database_name}'")
                if not temp_cursor.fetchone():
                    temp_cursor.execute(f"CREATE DATABASE {database_name}")
                
                temp_cursor.close()
                temp_conn.close()
            except:
                pass
            
            # Now create tables
            create_tables()
            return
            
        except Error:
            if attempt < max_retries - 1:
                import time
                time.sleep(1)
            else:
                create_essential_tables_only()

def create_essential_tables_only():
    """Create only essential tables if full creation fails"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY AUTO_INCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            )
        ''')
        
        # Create facts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS facts (
                id VARCHAR(50) PRIMARY KEY,
                description TEXT NOT NULL,
                value BOOLEAN DEFAULT FALSE,
                category VARCHAR(100) DEFAULT 'uncategorized'
            )
        ''')
        
        # Create rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id VARCHAR(50) PRIMARY KEY,
                conditions JSON,
                conclusion VARCHAR(100),
                certainty DECIMAL(3,2) DEFAULT 1.00,
                explanation TEXT,
                recommendation TEXT
            )
        ''')
        
        # Create taxonomy table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS taxonomy (
                id INT PRIMARY KEY AUTO_INCREMENT,
                child VARCHAR(100) NOT NULL,
                parent VARCHAR(100) NOT NULL,
                UNIQUE KEY unique_child (child)
            )
        ''')
        
        conn.commit()
        cursor.close()
        conn.close()
        
    except:
        pass

def startup_check():
    """Perform startup check without blocking"""
    import threading
    import time
    
    def delayed_init():
        time.sleep(2)
        try:
            init_database()
        except:
            pass
    
    thread = threading.Thread(target=delayed_init, daemon=True)
    thread.start()

# Start initialization in background
startup_check()