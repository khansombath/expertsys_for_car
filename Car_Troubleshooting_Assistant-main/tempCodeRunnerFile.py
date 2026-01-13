# app.py
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import os
import importlib.util
from jsonschema import validate, ValidationError
from datetime import datetime
from functools import wraps
from werkzeug.utils import secure_filename
import base64


# Import database functions
from database import (
    get_all_facts, get_fact, log_audit, save_fact, delete_fact,
    get_all_rules, save_rule, delete_rule,
    get_taxonomy, save_taxonomy, update_taxonomy_relationship, delete_taxonomy_relationship,
    get_history, save_history_item, delete_history_item,
    authenticate_user, create_user, get_user, update_user_role, get_all_users, update_user_profile,
    get_db_connection,get_audit_logs
)

# --- Setup ---
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Path to the schemas file
SCHEMAS_FILE = os.getenv(
    "SCHEMAS_FILE",
    os.path.join(APP_ROOT, "schemas", "schemas.py")
)

def _load_schemas_from_file(path: str):
    """Dynamically load facts/rules schemas from a Python file."""
    spec = importlib.util.spec_from_file_location("external_schemas", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"Cannot load schemas module from: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.facts_array_schema, module.rules_array_schema
    except AttributeError as e:
        raise AttributeError(
            f"'{path}' must expose 'facts_array_schema' and 'rules_array_schema'."
        ) from e

try:
    facts_array_schema, rules_array_schema = _load_schemas_from_file(SCHEMAS_FILE)
except Exception as e:
    raise RuntimeError(
        f"Failed to load JSON Schemas from '{SCHEMAS_FILE}': {e}.\n"
        "Ensure schemas/schemas.py exists and defines the required schemas."
    )

# --- Flask app & routes ---

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-this-in-production")

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.role = user_data['role']
        self.profile_picture = user_data.get('profile_picture')
        self._is_active = user_data.get('is_active', True)
    
    @property
    def is_active(self):
        return self._is_active
    
    @is_active.setter
    def is_active(self, value):
        self._is_active = bool(value)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_expert(self):
        return self.role == 'expert'
    
    def is_regular_user(self):
        return self.role == 'user'
    
    def can_edit(self):
        return self.role in ['admin', 'expert']
    
    def can_delete(self):
        return self.role == 'admin'
    
    def can_manage_users(self):
        return self.role == 'admin'
    
    def can_toggle_facts(self):
        return self.is_authenticated and self.is_active
    
    def can_view_facts(self):
        return self.is_authenticated and self.is_active

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user(user_id)
    if user_data:
        return User(user_data)
    return None

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# --- Custom Decorators ---
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash("Access denied. Admin privileges required.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def expert_or_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_edit():
            flash("Access denied. Expert or admin privileges required.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def can_edit_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_edit():
            flash("You don't have permission to edit content.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def can_delete_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_delete():
            flash("You don't have permission to delete content.", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helpers ---
def clamp01(x) -> float:
    try:
        value = float(x)
        # If value is between 0 and 100, treat as percentage
        if 0 <= value <= 100:
            if value > 1:  # Convert percentage to decimal
                value = value / 100.0
        return max(0.0, min(1.0, value))
    except Exception:
        return 0.0

def error_payload(e: ValidationError, filelabel: str):
    return {
        "file": filelabel,
        "error": e.message,
        "path": list(e.path),
        "schema_path": list(e.schema_path)
    }

# --- Taxonomy helpers ---
def get_taxonomy_data():
    taxonomy = get_taxonomy()
    return taxonomy.get("parent", {})

def ancestors(concept: str):
    parent_map = get_taxonomy_data()
    seen = set()
    cur = concept
    while cur in parent_map:
        parent = parent_map[cur]
        if parent in seen:
            break
        seen.add(parent)
        yield parent
        cur = parent

def expand_observations(obs_conf: dict) -> dict:
    parent_map = get_taxonomy_data()
    if not parent_map:
        return obs_conf

    expanded = dict(obs_conf)
    for fid, c in list(obs_conf.items()):
        for anc in ancestors(fid):
            expanded[anc] = max(expanded.get(anc, 0.0), c)
    return expanded

def evaluate_rule(rule: dict, obs_conf: dict):
    cond_ids = rule.get("conditions", [])
    if not cond_ids:
        return (False, 0.0)

    cond_scores = []
    for cid in cond_ids:
        c = clamp01(obs_conf.get(cid, 0.0))
        cond_scores.append(c)

    if min(cond_scores) <= 0.0:
        return (False, 0.0)

    base = min(cond_scores)
    cf = clamp01(rule.get("certainty", 1.0))
    return (True, base * cf)

def get_taxonomy_stats():
    try:
        facts = get_all_facts()
        taxonomy = get_taxonomy_data()
        
        if not facts or not taxonomy:
            return {
                "total_facts": 0,
                "facts_in_taxonomy": 0,
                "missing_facts": 0,
                "orphaned_facts": 0,
                "categorized_facts": 0,
                "uncategorized_facts": 0
            }

        all_fact_ids = {f["id"] for f in facts if "id" in f}
        taxonomy_fact_ids = set(taxonomy.keys())

        missing_facts = all_fact_ids - taxonomy_fact_ids
        orphaned_facts = taxonomy_fact_ids - all_fact_ids
        
        categorized_facts = [fid for fid in taxonomy_fact_ids
                             if taxonomy.get(fid) != "uncategorized"]
        uncategorized_facts = [fid for fid in taxonomy_fact_ids
                               if taxonomy.get(fid) == "uncategorized"]

        return {
            "total_facts": len(all_fact_ids),
            "facts_in_taxonomy": len(taxonomy_fact_ids & all_fact_ids),
            "missing_facts": len(missing_facts),
            "orphaned_facts": len(orphaned_facts),
            "categorized_facts": len(categorized_facts),
            "uncategorized_facts": len(uncategorized_facts)
        }
    except Exception:
        return {
            "total_facts": 0, "facts_in_taxonomy": 0, "missing_facts": 0,
            "orphaned_facts": 0, "categorized_facts": 0, "uncategorized_facts": 0
        }

def update_taxonomy_with_fact(fact_id, category):
    try:
        update_taxonomy_relationship(fact_id, category)

        category_hierarchy = {
            'electrical_symptom': 'electrical_issue',
            'starting_symptom': 'starting_issue',
            'running_symptom': 'running_issue',
            'fuel_symptom': 'fuel_issue',
            'environment_context': 'engine_problem',
            'uncategorized': 'engine_problem',
            'electrical_issue': 'engine_problem',
            'starting_issue': 'engine_problem',
            'running_issue': 'engine_problem',
            'fuel_issue': 'engine_problem',
            'diagnosed_issue': 'engine_problem'
        }

        for cat, parent in category_hierarchy.items():
            update_taxonomy_relationship(cat, parent)

    except Exception:
        pass

# --- File Upload Configuration ---
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Utility Context Processor ---
@app.context_processor
def utility_processor():
    def b64encode(data):
        if data:
            return base64.b64encode(data).decode('utf-8')
        return ''
    return dict(b64encode=b64encode)

# --- Authentication Routes ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        
        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template("login.html")
        
        user_data = authenticate_user(username, password)
        if user_data:
            user = User(user_data)
            login_user(user)
            flash(f"Welcome back, {username}!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash("Invalid username or password", "danger")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        
        if not username or not password:
            flash("Username and password are required", "danger")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", "danger")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long", "danger")
            return render_template("register.html")
        
        try:
            user_id = create_user(username, password, email)
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Registration failed: {str(e)}", "danger")
    
    return render_template("register.html")

# --- Dashboard Route ---
@app.route("/dashboard")
@login_required
def dashboard():
    permissions = {
        'can_view_facts': True,
        'can_view_rules': True,
        'can_use_inference': True,
        'can_view_history': True,
        'can_edit_facts': current_user.can_edit(),
        'can_edit_rules': current_user.can_edit(),
        'can_manage_taxonomy': current_user.can_edit(),
        'can_manage_users': current_user.is_admin(),
        'role': current_user.role
    }
    return render_template("dashboard.html", permissions=permissions)

# --- Protected Routes ---
@app.route("/")
@login_required
def home():
    stats = get_taxonomy_stats()
    facts_count = len(get_all_facts())
    rules_count = len(get_all_rules())
    return render_template(
        "home.html",
        facts_count=facts_count,
        rules_count=rules_count,
        stats=stats
    )

# --- Profile Routes ---
@app.route("/profile")
@login_required
def profile():
    try:
        user_data = get_user(current_user.id)
        if not user_data:
            flash("User not found", "danger")
            return redirect(url_for('home'))
        
        user_facts_count = 0
        user_rules_count = 0
        user_history_count = 0
        
        try:
            all_facts = get_all_facts()
            all_rules = get_all_rules()
            all_history = get_history()
            
            current_username = str(current_user.username)
            user_facts_count = len([f for f in all_facts if f.get('created_by') == current_username])
            user_rules_count = len([r for r in all_rules if r.get('created_by') == current_username])
            user_history_count = len([h for h in all_history if h.get('username') == current_username])
            
        except Exception:
            pass
        
        return render_template("profile.html",
                             user=user_data,
                             user_facts_count=user_facts_count,
                             user_rules_count=user_rules_count,
                             user_history_count=user_history_count)
                             
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", "danger")
        return redirect(url_for('home'))

@app.route("/profile/update", methods=["POST"])
@login_required
def update_profile():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    if not authenticate_user(current_user.username, current_password):
        flash("Current password is incorrect", "danger")
        return redirect(url_for('profile'))
    
    if new_password:
        if new_password != confirm_password:
            flash("New passwords do not match", "danger")
            return redirect(url_for('profile'))
        
        if len(new_password) < 6:
            flash("New password must be at least 6 characters long", "danger")
            return redirect(url_for('profile'))
    
    try:
        update_user_profile(current_user.id, username=username, email=email)
        
        if new_password:
            try:
                update_user_profile(current_user.id, password=new_password)
            except:
                pass
        
        flash("Profile updated successfully!", "success")
    except Exception as e:
        flash(f"Error updating profile: {str(e)}", "danger")
    
    return redirect(url_for('profile'))

@app.route("/profile/upload_picture", methods=["POST"])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    
    if file.filename == '':
        flash('No file selected', 'danger')
        return redirect(url_for('profile'))
    
    # Check file extension
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    
    if not allowed_file(file.filename):
        flash('Only image files (PNG, JPG, JPEG, GIF) are allowed', 'danger')
        return redirect(url_for('profile'))
    
    # Get file size
    file.seek(0, 2)  # Seek to end
    file_size = file.tell()
    file.seek(0)  # Seek back to start
    
    if file_size > MAX_FILE_SIZE:
        flash('File size must be less than 5MB', 'danger')
        return redirect(url_for('profile'))
    
    try:
        # Read file data
        file_data = file.read()
        
        # Determine MIME type based on file extension
        filename = file.filename.lower()
        if filename.endswith('.png'):
            mime_type = 'image/png'
        elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
            mime_type = 'image/jpeg'
        elif filename.endswith('.gif'):
            mime_type = 'image/gif'
        else:
            mime_type = 'image/jpeg'  # default
        
        # Encode to base64 WITH data URI prefix
        base64_data = base64.b64encode(file_data).decode('utf-8')
        data_uri = f"data:{mime_type};base64,{base64_data}"
        
        # Store in database
        update_user_profile(current_user.id, profile_picture=data_uri)
        
        flash('Profile picture uploaded successfully!', 'success')
        
    except Exception as e:
        print(f"Error uploading picture: {str(e)}")
        flash(f'Error uploading picture: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/profile/remove-picture', methods=['POST'])
@login_required
def remove_profile_picture():
    try:
        update_user_profile(current_user.id, profile_picture=None)
        flash("Profile picture removed successfully", "success")
        return redirect(url_for('profile'))
    except Exception as e:
        flash(f"Error removing picture: {e}", "danger")
        return redirect(url_for('profile'))

# --- Facts Routes ---
@app.get("/facts")
@login_required
def facts_list():
    fresh_facts = get_all_facts()
    return render_template("facts_list.html", facts=fresh_facts)

@app.route("/facts/new", methods=["GET", "POST"])
@expert_or_admin_required
def facts_new():
    if request.method == "POST":
        fid = (request.form.get("id") or "").strip()
        description = (request.form.get("description") or "").strip()
        value = request.form.get("value") == "on"
        tags_raw = request.form.get("tags") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        category = request.form.get("category", "uncategorized")

        if not fid:
            flash("ID is required", "danger")
            return render_template("fact_form.html", mode="new", fact={
                "id": fid, "description": description, "value": value, 
                "tags": tags, "category": category
            })

        existing_fact = get_fact(fid)
        if existing_fact:
            flash(f"Fact ID '{fid}' already exists", "danger")
            return render_template("fact_form.html", mode="new", fact={
                "id": fid, "description": description, "value": value, 
                "tags": tags, "category": category
            })

        new_item = {
            "id": fid, "description": description, "value": bool(value), 
            "tags": tags, "category": category
        }

        try:
            all_facts = get_all_facts()
            test_facts = all_facts + [new_item]
            validate(test_facts, facts_array_schema)
            save_fact(new_item, current_user.id)
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("fact_form.html", mode="new", fact=new_item)

        flash(f"Fact '{fid}' created with category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="new", fact=None)

@app.route("/facts/<fid>/edit", methods=["GET", "POST"])
@expert_or_admin_required
def facts_edit(fid):
    fact = get_fact(fid)
    if not fact:
        flash("Fact not found", "warning")
        return redirect(url_for("facts_list"))

    if request.method == "POST":
        description = (request.form.get("description") or "").strip()
        value = request.form.get("value") == "on"
        tags_raw = request.form.get("tags") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        category = request.form.get("category", "uncategorized")

        updated_fact = {
            "id": fid, "description": description, "value": bool(value), 
            "tags": tags, "category": category
        }

        try:
            all_facts = get_all_facts()
            test_facts = [updated_fact if f["id"] == fid else f for f in all_facts]
            validate(test_facts, facts_array_schema)
            save_fact(updated_fact, current_user.id)
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("fact_form.html", mode="edit", fact=updated_fact)

        flash(f"Fact '{fid}' updated with category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="edit", fact=fact)

@app.post("/facts/<fid>/delete")
@admin_required
def facts_delete(fid):
    delete_fact(fid, current_user.id)
    delete_taxonomy_relationship(fid, current_user.id)
    flash(f"Fact '{fid}' deleted from facts and taxonomy", "success")
    return redirect(url_for("facts_list"))

@app.route("/facts/toggle/<fid>", methods=["POST"])
@login_required
def facts_toggle(fid):
    try:
        fact = get_fact(fid)
        if fact:
            fact["value"] = not fact["value"]
            save_fact(fact, current_user.id)
            flash(f'Fact "{fid}" updated to {fact["value"]}', 'success')
        else:
            flash(f'Fact "{fid}" not found', 'error')
    except Exception as e:
        flash(f'Error toggling fact: {str(e)}', 'danger')
    return redirect(url_for('facts_list'))

# --- Rules Routes ---
@app.get("/rules")
@login_required
def rules_list():
    fresh_rules = get_all_rules()
    return render_template("rules_list.html", rules=fresh_rules)

@app.route("/rules/new", methods=["GET", "POST"])
@expert_or_admin_required
def rules_new():
    if request.method == "POST":
        rid = (request.form.get("id") or "").strip()
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        
        # Get certainty as string to preserve the original value
        certainty_str = request.form.get("certainty") or "80"
        # Convert to float for processing
        try:
            certainty = float(certainty_str)
            # If user entered percentage (e.g., 90), convert to decimal
            if certainty > 1:
                certainty = certainty / 100.0
            certainty = max(0.0, min(1.0, certainty))
        except (ValueError, TypeError):
            certainty = 0.8  # default
            
        explain = (request.form.get("explain") or "").strip()
        recommendation = (request.form.get("recommendation") or "").strip()
        conditions = [c.strip() for c in conditions_raw.split(",") if c.strip()]
        
        new_item = {
            "id": rid, "conditions": conditions, "conclusion": conclusion,
            "certainty": certainty, "explain": explain, "recommendation": recommendation
        }

        if not rid:
            flash("ID is required", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        all_rules = get_all_rules()
        if any(r.get("id") == rid for r in all_rules):
            flash(f"Rule ID '{rid}' already exists", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        try:
            test_rules = all_rules + [new_item]
            validate(test_rules, rules_array_schema)
            save_rule(new_item, current_user.id)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        flash("Rule created", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="new", rule={"certainty": 0.8})

@app.route("/rules/<rid>/edit", methods=["GET", "POST"])
@expert_or_admin_required
def rules_edit(rid):
    all_rules = get_all_rules()
    rule = next((r for r in all_rules if r.get("id") == rid), None)
    if not rule:
        flash("Rule not found", "warning")
        return redirect(url_for("rules_list"))

    if request.method == "POST":
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        
        # Get certainty as string to preserve the original value
        certainty_str = request.form.get("certainty") or "80"
        # Convert to float for processing
        try:
            certainty = float(certainty_str)
            # If user entered percentage (e.g., 90), convert to decimal
            if certainty > 1:
                certainty = certainty / 100.0
            certainty = max(0.0, min(1.0, certainty))
        except (ValueError, TypeError):
            certainty = rule.get("certainty", 0.8)
            
        explain = (request.form.get("explain") or "").strip()
        recommendation = (request.form.get("recommendation") or "").strip()

        updated = {
            "id": rule["id"],
            "conditions": [c.strip() for c in conditions_raw.split(",") if c.strip()],
            "conclusion": conclusion, "certainty": certainty,
            "explain": explain, "recommendation": recommendation
        }

        try:
            test_rules = [updated if r["id"] == rule["id"] else r for r in all_rules]
            validate(test_rules, rules_array_schema)
            save_rule(updated, current_user.id)
        except ValidationError as e:
            flash(f"Validation error: {e.message}", "danger")
            return render_template("rule_form.html", mode="edit", rule=updated)

        flash("Rule updated", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="edit", rule=rule)

@app.post("/rules/<rid>/delete")
@admin_required
def rules_delete(rid):
    delete_rule(rid, current_user.id)
    flash("Rule deleted", "success")
    return redirect(url_for("rules_list"))

# --- Taxonomy Routes ---
@app.get("/taxonomy")
@login_required
def taxonomy_view():
    stats = get_taxonomy_stats()
    taxonomy_data = get_taxonomy_data()
    facts_data = get_all_facts()
    fact_ids_in_taxonomy = [fid for fid in taxonomy_data.keys() if fid.startswith('f')]
    raw_json = json.dumps({"parent": taxonomy_data}, indent=2, ensure_ascii=False)
    return render_template("taxonomy.html",
                         taxonomy={"parent": taxonomy_data}, raw_json=raw_json, stats=stats,
                         facts=facts_data, fact_ids_in_taxonomy=fact_ids_in_taxonomy)

@app.post("/taxonomy/add_missing_facts")
@expert_or_admin_required
def taxonomy_add_missing_facts():
    try:
        facts_data = get_all_facts()
        taxonomy_data = get_taxonomy_data()
        missing_count = 0
        added_facts = []
        for fact in facts_data:
            fid = fact["id"]
            if fid not in taxonomy_data:
                update_taxonomy_relationship(fid, "uncategorized", current_user.id)
                missing_count += 1
                added_facts.append(fid)
        
        if missing_count > 0:
            flash(f"Added {missing_count} facts to taxonomy", "success")
        else:
            flash("All facts are already in taxonomy", "info")
    except Exception as e:
        flash(f"Error adding missing facts: {str(e)}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.post("/taxonomy/add_rule_conclusions")
@expert_or_admin_required
def taxonomy_add_rule_conclusions():
    try:
        rules_data = get_all_rules()
        facts_data = get_all_facts()
        taxonomy_data = get_taxonomy_data()
        added_count = 0
        added_conclusions = []
        for rule in rules_data:
            conclusion = rule["conclusion"]
            if (not any(f["id"] == conclusion for f in facts_data) and 
                conclusion not in taxonomy_data):
                update_taxonomy_relationship(conclusion, "diagnosed_issue", current_user.id)
                added_count += 1
                added_conclusions.append(conclusion)
        
        if "diagnosed_issue" not in taxonomy_data:
            update_taxonomy_relationship("diagnosed_issue", "engine_problem", current_user.id)

        if added_count > 0:
            flash(f"Added {added_count} rule conclusions to taxonomy", "success")
        else:
            flash("All rule conclusions are already in taxonomy", "info")
    except Exception as e:
        flash(f"Error adding rule conclusions: {e}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.post("/taxonomy")
@expert_or_admin_required
def taxonomy_save():
    raw = request.form.get("raw_json") or "{}"
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Taxonomy must be a JSON object (dictionary).")
        if "parent" in parsed and not isinstance(parsed["parent"], dict):
            raise ValueError("taxonomy.parent must be a JSON object (dictionary).")
        save_taxonomy(parsed, current_user.id)
        flash("Taxonomy saved", "success")
    except Exception as e:
        flash(f"Failed to save taxonomy: {e}", "danger")
        taxonomy_data = get_taxonomy_data()
        return render_template("taxonomy.html", taxonomy={"parent": taxonomy_data}, raw_json=raw)
    return redirect(url_for("taxonomy_view"))

@app.route("/update_fact_category", methods=["POST"])
@expert_or_admin_required
def update_fact_category():
    try:
        fact_id = request.form.get("fact_id")
        category = request.form.get("category")
        if not fact_id:
            flash("Fact ID is required", "danger")
            return redirect(url_for("taxonomy_view"))
        
        if category:
            update_taxonomy_relationship(fact_id, category, current_user.id)
        else:
            delete_taxonomy_relationship(fact_id, current_user.id)
        
        flash(f"Updated category for fact {fact_id}", "success")
    except Exception as e:
        flash(f"Error updating category: {str(e)}", "danger")
    return redirect(url_for("taxonomy_view"))

@app.route("/sync_all_categories")
@expert_or_admin_required
def sync_all_categories():
    try:
        facts_data = get_all_facts()
        updated_count = 0
        for fact in facts_data:
            fact_id = fact['id']
            category = fact.get('category', 'uncategorized')
            update_taxonomy_with_fact(fact_id, category)
            updated_count += 1
        flash(f"Synced {updated_count} facts to taxonomy", "success")
    except Exception as e:
        flash(f"Error syncing categories: {e}", "danger")
    return redirect(url_for('taxonomy_view'))

# --- Inference Routes ---
@app.route("/infer", methods=["GET", "POST"])
@login_required
def infer():
    facts_data = get_all_facts()
    rules_data = get_all_rules()
    active_facts = [fact for fact in facts_data if fact.get("value", False)]
    
    if request.method == "POST":
        try:
            obs_conf = {}
            for fact in active_facts:
                fid = fact["id"]
                confidence_str = request.form.get(f"conf_{fid}", "0.0")
                try:
                    confidence = clamp01(float(confidence_str))
                    obs_conf[fid] = confidence
                except ValueError:
                    obs_conf[fid] = 0.0

            expanded_obs = expand_observations(obs_conf)
            results = []
            for rule in rules_data:
                fired, confidence = evaluate_rule(rule, expanded_obs)
                if fired:
                    results.append({
                        "rule_id": rule["id"], "conclusion": rule["conclusion"],
                        "confidence": confidence, "explanation": rule.get("explain", ""),
                        "triggered_conditions": rule["conditions"],
                        "recommendation": rule.get("recommendation", ""),
                        "severity": rule.get("severity", "medium"),
                    })

            results.sort(key=lambda x: x["confidence"], reverse=True)
            session['obs_conf'] = obs_conf
            session['results'] = results
            session['expanded_obs'] = expanded_obs
            session.modified = True

            try:
                history_item = {
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                    "observations": obs_conf, "expanded_obs": expanded_obs, "results": results
                }
                save_history_item(history_item, current_user.id)
                flash("Diagnosis completed and saved to history", "success")
            except Exception:
                flash("Diagnosis completed but could not save to history", "warning")

            return render_template("infer.html", facts=active_facts, obs_conf=obs_conf,
                                 results=results, expanded_obs=expanded_obs)
            
        except Exception as e:
            flash(f"Inference error: {str(e)}", "danger")
            return redirect(url_for("infer"))
    
    obs_conf = session.get('obs_conf', {})
    results = session.get('results', [])
    expanded_obs = session.get('expanded_obs', {})
    return render_template("infer.html", facts=active_facts, results=results, 
                         obs_conf=obs_conf, expanded_obs=expanded_obs)

@app.route("/reset_inference", methods=["POST"])
@login_required
def reset_inference():
    session.pop('obs_conf', None)
    session.pop('results', None)
    session.pop('expanded_obs', None)
    session.modified = True
    flash("All confidence values and results have been reset", "success")
    return redirect(url_for("infer"))

# --- History Routes ---
@app.route("/history")
@login_required
def history_list():
    try:
        items = get_history(current_user.id)
        if items is None:
            items = []
            
        items = sorted(items, key=lambda x: x.get("id", 0))

        processed_items = []
        for item in items:
            processed_item = dict(item)
            
            if processed_item.get("timestamp"):
                processed_item["formatted_timestamp"] = processed_item["timestamp"].replace('T', ' ')
            else:
                processed_item["formatted_timestamp"] = "Unknown time"
            
            if processed_item.get("results"):
                sorted_results = sorted(processed_item["results"], key=lambda r: r.get("confidence", 0), reverse=True)
                if sorted_results:
                    top = sorted_results[0]
                    processed_item["top_conclusion"] = top.get("conclusion", "Unknown")
                    confidence_value = top.get("confidence", 0)
                    confidence_value = max(0.0, min(1.0, float(confidence_value)))
                    processed_item["top_confidence"] = int(confidence_value * 100)
                else:
                    processed_item["top_conclusion"] = "No conclusions"
                    processed_item["top_confidence"] = 0
            else:
                processed_item["top_conclusion"] = "No diagnosis results"
                processed_item["top_confidence"] = 0
            
            processed_items.append(processed_item)

        return render_template("history_list.html", items=processed_items)
    
    except Exception as e:
        flash("Error loading history", "danger")
        return render_template("history_list.html", items=[])

@app.route("/history/<int:hid>")
@login_required
def history_detail(hid):
    items = get_history(current_user.id)
    item = next((x for x in items if x.get("id") == hid), None)
    if not item:
        flash("History item not found", "warning")
        return redirect(url_for("history_list"))
    return render_template("history_detail.html", item=item)

@app.route("/history/delete/<int:hid>", methods=["POST"])
@login_required
def delete_history(hid):
    delete_history_item(hid, current_user.id)
    flash(f"History item deleted", "success")
    return redirect(url_for("history_list"))

# --- User Management Routes ---
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    try:
        users_data = get_all_users()
        users_data = sorted(users_data, key=lambda x: x['id'])
        users = [User(user_data) for user_data in users_data]
        
        # Get audit logs (last 50 entries)
        audit_logs = get_audit_logs(limit=50)
        
        # Process audit logs to handle datetime
        for log in audit_logs:
            if log.get('created_at'):
                # If it's already a datetime object, keep it
                if not isinstance(log['created_at'], str):
                    # Convert datetime to string if needed
                    pass
        
        try:
            facts_data = get_all_facts()
            facts_count = len(facts_data) if facts_data else 0
        except:
            facts_count = 0
            
        try:
            rules_data = get_all_rules()
            rules_count = len(rules_data) if rules_data else 0
        except:
            rules_count = 0
        
        current_time = datetime.now()
        
        return render_template(
            "admin_users.html",
            users=users,
            audit_logs=audit_logs,
            facts_count=facts_count,
            rules_count=rules_count,
            current_time=current_time
        )
    except Exception as e:
        flash(f'Error loading admin dashboard: {str(e)}', 'danger')
        return redirect(url_for('home'))

@app.route("/admin/users/<int:user_id>/update_role", methods=["POST"])
@admin_required
def admin_update_user_role(user_id):
    new_role = request.form.get("role")
    if new_role in ['admin', 'expert', 'user']:
        try:
            # Get the user before updating
            user = get_user(user_id)
            old_value = {'role': user['role']} if user else None
            
            # Update the role
            success = update_user_role(user_id, new_role)
            
            if success:
                # Log the audit event
                log_audit(
                    user_id=current_user.id,
                    action='UPDATE',
                    table_name='users',
                    record_id=user_id,
                    old_value=old_value,
                    new_value={'role': new_role},
                    ip_address=request.remote_addr,
                    user_agent=request.user_agent.string
                )
                flash(f"User role updated to {new_role}", "success")
            else:
                flash("Failed to update user role", "danger")
        except Exception as e:
            flash(f"Error: {str(e)}", "danger")
    else:
        flash("Invalid role", "danger")
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/add", methods=["POST"])
@admin_required
def admin_add_user():
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    role = request.form.get("role", "user")
    
    if not username or not password:
        flash("Username and password are required", "danger")
        return redirect(url_for('admin_users'))
    
    if password != confirm_password:
        flash("Passwords do not match", "danger")
        return redirect(url_for('admin_users'))
    
    if len(password) < 6:
        flash("Password must be at least 6 characters long", "danger")
        return redirect(url_for('admin_users'))
    
    try:
        user_id = create_user(username, password, email, role)
        
        # Log the audit event
        from database import log_audit
        log_audit(
            user_id=current_user.id,
            action='CREATE',
            table_name='users',
            record_id=user_id,
            old_value=None,
            new_value={'username': username, 'email': email, 'role': role},
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        flash(f"User '{username}' created successfully", "success")
    except Exception as e:
        flash(f"Failed to create user: {str(e)}", "danger")
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/toggle/<int:user_id>", methods=["POST"])
@admin_required
def admin_toggle_user_status(user_id):
    if user_id == current_user.id:
        flash("Cannot change your own status", "warning")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if user:
            new_status = not user['is_active']
            
            # Log the old value
            old_value = {'is_active': user['is_active']}
            
            cursor.execute(
                "UPDATE users SET is_active = %s WHERE id = %s",
                (new_status, user_id)
            )
            
            # Log the audit event
            log_audit(
                user_id=current_user.id,
                action='UPDATE',
                table_name='users',
                record_id=user_id,
                old_value=old_value,
                new_value={'is_active': new_status},
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            conn.commit()
            
            status_text = "enabled" if new_status else "disabled"
            flash(f"User {status_text} successfully", "success")
        else:
            flash("User not found", "warning")
            
    except Exception as e:
        flash(f"Failed to update user status: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_users'))
@app.route("/admin/users/edit", methods=["POST"])
@admin_required
def admin_edit_user():
    user_id = request.form.get("user_id")
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    confirm_password = request.form.get("confirm_password", "")
    
    if not user_id:
        flash("User ID is required", "danger")
        return redirect(url_for('admin_users'))
    
    if not username:
        flash("Username is required", "danger")
        return redirect(url_for('admin_users'))
    
    if password and password != confirm_password:
        flash("Passwords do not match", "danger")
        return redirect(url_for('admin_users'))
    
    if password and len(password) < 6:
        flash("Password must be at least 6 characters long", "danger")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get old user data for audit log
        cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
        old_user = cursor.fetchone()
        
        cursor.execute(
            "SELECT id FROM users WHERE username = %s AND id != %s",
            (username, user_id)
        )
        if cursor.fetchone():
            flash(f"Username '{username}' already exists", "danger")
            return redirect(url_for('admin_users'))
        
        update_fields = ["username = %s", "email = %s"]
        params = [username, email]
        
        if password:
            import hashlib
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            update_fields.append("password_hash = %s")
            params.append(password_hash)
        
        params.append(user_id)
        
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
        cursor.execute(query, params)
        conn.commit()
        
        # Log the audit event
        old_value = {'username': old_user['username'], 'email': old_user['email']} if old_user else None
        new_value = {'username': username, 'email': email}
        if password:
            new_value['password'] = '******'  # Don't log actual password
        
        log_audit(
            user_id=current_user.id,
            action='UPDATE',
            table_name='users',
            record_id=user_id,
            old_value=old_value,
            new_value=new_value,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        flash(f"User '{username}' updated successfully", "success")
        
    except Exception as e:
        flash(f"Failed to update user: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    user_id = request.form.get("user_id")
    
    if not user_id:
        flash("User ID is required", "danger")
        return redirect(url_for('admin_users'))
    
    if int(user_id) == current_user.id:
        flash("Cannot delete your own account", "warning")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # Get user data for audit log before deleting
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if not user:
            flash("User not found", "warning")
            return redirect(url_for('admin_users'))
        
        # Delete the user
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        # Log the audit event
        log_audit(
            user_id=current_user.id,
            action='DELETE',
            table_name='users',
            record_id=user_id,
            old_value=user,
            new_value=None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        conn.commit()
        
        flash(f"User deleted successfully", "success")
        
    except Exception as e:
        flash(f"Failed to delete user: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_users'))

# Add to your app.py

@app.route("/admin/audit/delete/<int:log_id>", methods=["POST"])
@admin_required
def delete_audit_log(log_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_log WHERE id = %s", (log_id,))
        conn.commit()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/audit/delete-batch", methods=["POST"])
@admin_required
def delete_audit_logs_batch():
    try:
        data = request.get_json()
        log_ids = data.get('log_ids', [])
        
        if not log_ids:
            return jsonify({"success": False, "error": "No log IDs provided"})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Convert list to tuple for SQL IN clause
        placeholders = ', '.join(['%s'] * len(log_ids))
        query = f"DELETE FROM audit_log WHERE id IN ({placeholders})"
        cursor.execute(query, tuple(log_ids))
        conn.commit()
        
        return jsonify({"success": True, "deleted": cursor.rowcount})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route("/admin/audit/export/<int:log_id>")
@admin_required
def export_audit_log(log_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM audit_log WHERE id = %s", (log_id,))
        log = cursor.fetchone()
        
        if log:
            # Convert to JSON file
            response = jsonify(log)
            response.headers['Content-Disposition'] = f'attachment; filename=audit_log_{log_id}.json'
            return response
        else:
            flash("Log not found", "danger")
            return redirect(url_for('admin_users'))
    except Exception as e:
        flash(f"Export failed: {str(e)}", "danger")
        return redirect(url_for('admin_users'))

@app.route("/admin/audit/export-batch")
@admin_required
def export_audit_logs_batch():
    try:
        log_ids = request.args.get('ids', '').split(',')
        if not log_ids or log_ids[0] == '':
            flash("No logs selected", "warning")
            return redirect(url_for('admin_users'))
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        placeholders = ', '.join(['%s'] * len(log_ids))
        query = f"SELECT * FROM audit_log WHERE id IN ({placeholders}) ORDER BY created_at DESC"
        cursor.execute(query, tuple(log_ids))
        logs = cursor.fetchall()
        
        # Convert to JSON file
        response = jsonify(logs)
        response.headers['Content-Disposition'] = f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return response
    except Exception as e:
        flash(f"Export failed: {str(e)}", "danger")
        return redirect(url_for('admin_users'))

# --- Other Routes ---
@app.get("/readme")
def readme():
    return render_template("README.html")

@app.get("/debug")
@login_required
def debug_stats():
    stats = get_taxonomy_stats()
    facts_count = len(get_all_facts())
    taxonomy_data = get_taxonomy_data()
    return jsonify({
        "stats": stats,
        "facts_count": facts_count,
        "taxonomy_keys": list(taxonomy_data.keys())[:5] if taxonomy_data else "No taxonomy"
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")