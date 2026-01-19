# app.py - Car Troubleshooting Assistant in Khmer
from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import os
import importlib.util
from jsonschema import validate, ValidationError
from datetime import datetime,date
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
    """បង្កើត facts/rules schemas ពីឯកសារ Python"""
    spec = importlib.util.spec_from_file_location("external_schemas", path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"មិនអាចទាញយក module schemas ពី: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    try:
        return module.facts_array_schema, module.rules_array_schema
    except AttributeError as e:
        raise AttributeError(
            f"'{path}' ត្រូវតែមាន 'facts_array_schema' និង 'rules_array_schema'"
        ) from e

try:
    facts_array_schema, rules_array_schema = _load_schemas_from_file(SCHEMAS_FILE)
except Exception as e:
    raise RuntimeError(
        f"មិនអាចទាញយក JSON Schemas ពី '{SCHEMAS_FILE}': {e}.\n"
        "ត្រូវប្រាកដថា schemas/schemas.py មាន និងបានកំណត់ schemas ដែលត្រូវការ"
    )

# --- Flask app & routes ---

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-change-this-in-production")

# --- Flask-Login Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'សូមចូលគណនីដើម្បីចូលទៅកាន់ទំព័រនេះ'
login_manager.login_message_category = 'warning'


class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data.get('email')
        self.role = user_data['role']
        self._is_active = user_data.get('is_active', True)
        self.profile_picture = user_data.get('profile_picture') 
    
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
    # ទាញយកទិន្នន័យអ្នកប្រើប្រាស់ថ្មីជាមួយរូបថតប្រវត្តិរូប
    if hasattr(current_user, 'is_authenticated') and current_user.is_authenticated:
        try:
            user_data = get_user(current_user.id)
            if user_data:
                user_obj = User(user_data)
                return dict(current_user=user_obj)
        except:
            pass
    return dict(current_user=current_user)

# --- Custom Decorators ---
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash("បដិសេធ។ ត្រូវការសិទ្ធិជាអ្នកគ្រប់គ្រង", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def expert_or_admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_edit():
            flash("បដិសេធ។ ត្រូវការសិទ្ធិជាអ្នកជំនាញ ឬអ្នកគ្រប់គ្រង", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def can_edit_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_edit():
            flash("អ្នកមិនមានសិទ្ធិកែសម្រួលមាតិកា", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def can_delete_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.can_delete():
            flash("អ្នកមិនមានសិទ្ធិលុបមាតិកា", "danger")
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helpers ---

def clamp01(x) -> float:
    try:
        value = float(x)
        # ប្រសិនបើតម្លៃមានចន្លោះពី 0 ទៅ 100 ពិចារណាថាជាភាគរយ
        if 0 <= value <= 100:
            if value > 1:  # បំលែងភាគរយទៅជាទសភាគ
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
            flash("ឈ្មោះអ្នកប្រើប្រាស់ និងពាក្យសម្ងាត់ត្រូវបំពេញ", "danger")
            return render_template("login.html")
        
        user_data = authenticate_user(username, password)
        if user_data:
            user = User(user_data)
            login_user(user)
            flash(f"ស្វាគមន៍ការត្រឡប់មកវិញ, {username}!", "success")
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            flash("ឈ្មោះអ្នកប្រើប្រាស់ ឬពាក្យសម្ងាត់មិនត្រឹមត្រូវ", "danger")
    
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("អ្នកបានចាកចេញពីគណនី", "info")
    return redirect(url_for('login'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        
        if not username or not password:
            flash("ឈ្មោះអ្នកប្រើប្រាស់ និងពាក្យសម្ងាត់ត្រូវបំពេញ", "danger")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("ពាក្យសម្ងាត់មិនដូចគ្នា", "danger")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ", "danger")
            return render_template("register.html")
        
        try:
            user_id = create_user(username, password, email)
            flash("ចុះឈ្មោះជោគជ័យ! សូមចូលគណនី", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"ចុះឈ្មោះមិនបានសម្រេច: {str(e)}", "danger")
    
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
            flash("រកមិនឃើញអ្នកប្រើប្រាស់", "danger")
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
        flash(f"កំហុសក្នុងការទាញយកប្រវត្តិរូប: {str(e)}", "danger")
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
        flash("ពាក្យសម្ងាត់បច្ចុប្បន្នមិនត្រឹមត្រូវ", "danger")
        return redirect(url_for('profile'))
    
    if new_password:
        if new_password != confirm_password:
            flash("ពាក្យសម្ងាត់ថ្មីមិនដូចគ្នា", "danger")
            return redirect(url_for('profile'))
        
        if len(new_password) < 6:
            flash("ពាក្យសម្ងាត់ថ្មីត្រូវមានយ៉ាងតិច ៦ តួអក្សរ", "danger")
            return redirect(url_for('profile'))
    
    try:
        update_user_profile(current_user.id, username=username, email=email)
        
        if new_password:
            try:
                update_user_profile(current_user.id, password=new_password)
            except:
                pass
        
        flash("បានធ្វើបច្ចុប្បន្នភាពប្រវត្តិរូបដោយជោគជ័យ!", "success")
    except Exception as e:
        flash(f"កំហុសក្នុងការធ្វើបច្ចុប្បន្នភាពប្រវត្តិរូប: {str(e)}", "danger")
    
    return redirect(url_for('profile'))

@app.route("/profile/upload_picture", methods=["POST"])
@login_required
def upload_profile_picture():
    if 'profile_picture' not in request.files:
        flash('មិនមានឯកសារបានជ្រើសរើស', 'danger')
        return redirect(url_for('profile'))
    
    file = request.files['profile_picture']
    
    if file.filename == '':
        flash('មិនមានឯកសារបានជ្រើសរើស', 'danger')
        return redirect(url_for('profile'))
    
    if not allowed_file(file.filename):
        flash('អនុញ្ញាតតែឯកសាររូបភាព (PNG, JPG, JPEG, GIF)', 'danger')
        return redirect(url_for('profile'))
    
    if file.content_length > MAX_FILE_SIZE:
        flash('ទំហំឯកសារត្រូវតែតូចជាង 5MB', 'danger')
        return redirect(url_for('profile'))
    
    try:
        file_data = file.read()
        update_user_profile(current_user.id, profile_picture=file_data)
        flash('បានផ្ទុករូបថតប្រវត្តិរូបដោយជោគជ័យ!', 'success')
    except Exception as e:
        flash(f'កំហុសក្នុងការផ្ទុករូបថត: {str(e)}', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/profile/remove-picture', methods=['POST'])
@login_required
def remove_profile_picture():
    try:
        update_user_profile(current_user.id, profile_picture=None)
        flash("បានដករូបថតប្រវត្តិរូបចេញ", "success")
        return redirect(url_for('profile'))
    except Exception as e:
        flash(f"កំហុសក្នុងការដករូបថត: {e}", "danger")
        return redirect(url_for('profile'))

# --- Facts Routes ---
@app.get("/facts")
@login_required
def facts_list():
    fresh_facts = get_all_facts()
    return render_template("facts_list.html", facts=fresh_facts)
#
# new fact for update to day 18 january 2026
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
            flash("ត្រូវការ ID", "danger")
            return render_template("fact_form.html", mode="new", fact={
                "id": fid, "description": description, "value": value, 
                "tags": tags, "category": category
            })

        existing_fact = get_fact(fid)
        if existing_fact:
            flash(f"Fact ID '{fid}' មានរួចហើយ", "danger")
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
            
            # Save fact and log audit
            old_value = None  # New creation, no old value
            new_value = dict(new_item)
            
            # Save to database
            save_fact(new_item, current_user.id)
            
            # Log audit - CREATE action
            log_audit(
                user_id=current_user.id,
                action='CREATE',
                table_name='facts',
                record_id=fid,
                old_value=old_value,
                new_value=new_value,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"កំហុសផ្ទៀងផ្ទាត់: {e.message}", "danger")
            return render_template("fact_form.html", mode="new", fact=new_item)

        flash(f"បានបង្កើត Fact '{fid}' ជាមួយ category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="new", fact=None)

#  fact edit for update to day 18 january 2026
@app.route("/facts/<fid>/edit", methods=["GET", "POST"])
@expert_or_admin_required
def facts_edit(fid):
    fact = get_fact(fid)
    if not fact:
        flash("រកមិនឃើញ Fact", "warning")
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
            
            # Get old value before saving
            old_value = dict(fact) if fact else None
            
            # Save updated fact
            save_fact(updated_fact, current_user.id)
            
            # Log audit - UPDATE action
            log_audit(
                user_id=current_user.id,
                action='UPDATE',
                table_name='facts',
                record_id=fid,
                old_value=old_value,
                new_value=updated_fact,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            update_taxonomy_with_fact(fid, category)
        except ValidationError as e:
            flash(f"កំហុសផ្ទៀងផ្ទាត់: {e.message}", "danger")
            return render_template("fact_form.html", mode="edit", fact=updated_fact)

        flash(f"បានធ្វើបច្ចុប្បន្នភាព Fact '{fid}' ជាមួយ category '{category}'", "success")
        return redirect(url_for("facts_list"))

    return render_template("fact_form.html", mode="edit", fact=fact)

# fact delete for update to day 18 january 2026
@app.post("/facts/<fid>/delete")
@admin_required
def facts_delete(fid):
    # Get fact before deletion for audit logging
    fact = get_fact(fid)
    if fact:
        old_value = dict(fact)
    else:
        old_value = None
    
    # Delete the fact
    delete_fact(fid, current_user.id)
    delete_taxonomy_relationship(fid, current_user.id)
    
    # Log audit - DELETE action (already done in delete_fact function)
    # No need to log again since delete_fact already logs
    
    flash(f"បានលុប Fact '{fid}' ពី facts និង taxonomy", "success")
    return redirect(url_for("facts_list"))

# fact toggle for update to day 18 january 2026
@app.route("/facts/toggle/<fid>", methods=["POST"])
@login_required
def facts_toggle(fid):
    try:
        fact = get_fact(fid)
        if fact:
            # Get old value before toggling
            old_value = dict(fact)
            
            # Toggle the value
            fact["value"] = not fact["value"]
            
            # Save the updated fact
            save_fact(fact, current_user.id)
            
            # Log audit - UPDATE action
            log_audit(
                user_id=current_user.id,
                action='UPDATE',
                table_name='facts',
                record_id=fid,
                old_value=old_value,
                new_value=fact,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            
            flash(f'បានធ្វើបច្ចុប្បន្នភាព Fact "{fid}" ទៅ {fact["value"]}', 'success')
        else:
            flash(f'រកមិនឃើញ Fact "{fid}"', 'error')
    except Exception as e:
        flash(f'កំហុសក្នុងការប្តូរ Fact: {str(e)}', 'danger')
    return redirect(url_for('facts_list'))

# --- Rules Routes ---
@app.get("/rules")
@login_required
def rules_list():
    fresh_rules = get_all_rules()
    return render_template("rules_list.html", rules=fresh_rules)

# rule new for update to day 18 january 2026
@app.route("/rules/new", methods=["GET", "POST"])
@expert_or_admin_required
def rules_new():
    if request.method == "POST":
        rid = (request.form.get("id") or "").strip()
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        
        certainty_str = request.form.get("certainty") or "80"
        try:
            certainty = float(certainty_str)
            if certainty > 1:
                certainty = certainty / 100.0
            certainty = max(0.0, min(1.0, certainty))
        except (ValueError, TypeError):
            certainty = 0.8
            
        explain = (request.form.get("explain") or "").strip()
        recommendation = (request.form.get("recommendation") or "").strip()
        conditions = [c.strip() for c in conditions_raw.split(",") if c.strip()]
        
        new_item = {
            "id": rid, "conditions": conditions, "conclusion": conclusion,
            "certainty": certainty, "explain": explain, "recommendation": recommendation
        }

        if not rid:
            flash("ត្រូវការ ID", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        all_rules = get_all_rules()
        if any(r.get("id") == rid for r in all_rules):
            flash(f"Rule ID '{rid}' មានរួចហើយ", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        try:
            test_rules = all_rules + [new_item]
            validate(test_rules, rules_array_schema)
            
            # Save rule and log audit
            old_value = None  # New creation, no old value
            
            # Save to database
            save_rule(new_item, current_user.id)
            
            # Log audit - CREATE action
            log_audit(
                user_id=current_user.id,
                action='CREATE',
                table_name='rules',
                record_id=rid,
                old_value=old_value,
                new_value=new_item,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
        except ValidationError as e:
            flash(f"កំហុសផ្ទៀងផ្ទាត់: {e.message}", "danger")
            return render_template("rule_form.html", mode="new", rule=new_item)

        flash("បានបង្កើត Rule", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="new", rule={"certainty": 0.8})

# rule edit for update to day 18 january 2026
@app.route("/rules/<rid>/edit", methods=["GET", "POST"])
@expert_or_admin_required
def rules_edit(rid):
    all_rules = get_all_rules()
    rule = next((r for r in all_rules if r.get("id") == rid), None)
    if not rule:
        flash("រកមិនឃើញ Rule", "warning")
        return redirect(url_for("rules_list"))

    if request.method == "POST":
        conditions_raw = (request.form.get("conditions") or "").strip()
        conclusion = (request.form.get("conclusion") or "").strip()
        
        certainty_str = request.form.get("certainty") or "80"
        try:
            certainty = float(certainty_str)
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
            
            # Get old value before saving
            old_value = dict(rule) if rule else None
            
            # Save updated rule
            save_rule(updated, current_user.id)
            
            # Log audit - UPDATE action
            log_audit(
                user_id=current_user.id,
                action='UPDATE',
                table_name='rules',
                record_id=rid,
                old_value=old_value,
                new_value=updated,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
        except ValidationError as e:
            flash(f"កំហុសផ្ទៀងផ្ទាត់: {e.message}", "danger")
            return render_template("rule_form.html", mode="edit", rule=updated)

        flash("បានធ្វើបច្ចុប្បន្នភាព Rule", "success")
        return redirect(url_for("rules_list"))

    return render_template("rule_form.html", mode="edit", rule=rule)

# rule delete for update to day 18 january 2026
@app.post("/rules/<rid>/delete")
@admin_required
def rules_delete(rid):
    # Get rule before deletion for audit logging
    all_rules = get_all_rules()
    rule = next((r for r in all_rules if r.get("id") == rid), None)
    
    if rule:
        old_value = dict(rule)
    else:
        old_value = None
    
    # Delete the rule (function already logs audit in database.py)
    delete_rule(rid, current_user.id)
    
    flash("បានលុប Rule", "success")
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
            flash(f"បានបន្ថែម facts {missing_count} ទៅ taxonomy", "success")
        else:
            flash("រាល់ facts ទាំងអស់មាននៅក្នុង taxonomy រួចហើយ", "info")
    except Exception as e:
        flash(f"កំហុសក្នុងការបន្ថែម facts ដែលបាត់: {str(e)}", "danger")
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
            flash(f"បានបន្ថែម rule conclusions {added_count} ទៅ taxonomy", "success")
        else:
            flash("រាល់ rule conclusions ទាំងអស់មាននៅក្នុង taxonomy រួចហើយ", "info")
    except Exception as e:
        flash(f"កំហុសក្នុងការបន្ថែម rule conclusions: {e}", "danger")
    return redirect(url_for("taxonomy_view"))

# taxonomy save for update to day 18 january 2026
@app.post("/taxonomy")
@expert_or_admin_required
def taxonomy_save():
    raw = request.form.get("raw_json") or "{}"
    try:
        parsed = json.loads(raw)
        if not isinstance(parsed, dict):
            raise ValueError("Taxonomy ត្រូវតែជា JSON object (វចនានុក្រម)")
        if "parent" in parsed and not isinstance(parsed["parent"], dict):
            raise ValueError("taxonomy.parent ត្រូវតែជា JSON object (វចនានុក្រម)")
        
        # Get old taxonomy before saving
        old_taxonomy = get_taxonomy()
        
        # Save new taxonomy
        save_taxonomy(parsed, current_user.id)
        
        # Log audit - UPDATE action
        log_audit(
            user_id=current_user.id,
            action='UPDATE',
            table_name='taxonomy',
            record_id='all',
            old_value=old_taxonomy,
            new_value=parsed,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        flash("បានរក្សាទុក taxonomy", "success")
    except Exception as e:
        flash(f"មិនអាចរក្សាទុក taxonomy: {e}", "danger")
        taxonomy_data = get_taxonomy_data()
        return render_template("taxonomy.html", taxonomy={"parent": taxonomy_data}, raw_json=raw)
    return redirect(url_for("taxonomy_view"))
#
# taxonomy update fact category for update to day 18 january 2026
@app.route("/update_fact_category", methods=["POST"])
@expert_or_admin_required
def update_fact_category():
    try:
        fact_id = request.form.get("fact_id")
        category = request.form.get("category")
        if not fact_id:
            flash("ត្រូវការ Fact ID", "danger")
            return redirect(url_for("taxonomy_view"))
        
        # Get old taxonomy relationship
        taxonomy_data = get_taxonomy_data()
        old_category = taxonomy_data.get(fact_id)
        
        if category:
            update_taxonomy_relationship(fact_id, category, current_user.id)
            
            # Log audit - UPDATE action
            log_audit(
                user_id=current_user.id,
                action='UPDATE',
                table_name='taxonomy',
                record_id=fact_id,
                old_value={'child': fact_id, 'parent': old_category} if old_category else None,
                new_value={'child': fact_id, 'parent': category},
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
        else:
            delete_taxonomy_relationship(fact_id, current_user.id)
            
            # Log audit - DELETE action
            log_audit(
                user_id=current_user.id,
                action='DELETE',
                table_name='taxonomy',
                record_id=fact_id,
                old_value={'child': fact_id, 'parent': old_category} if old_category else None,
                new_value=None,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
        
        flash(f"បានធ្វើបច្ចុប្បន្នភាព category សម្រាប់ fact {fact_id}", "success")
    except Exception as e:
        flash(f"កំហុសក្នុងការធ្វើបច្ចុប្បន្នភាព category: {str(e)}", "danger")
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
        flash(f"បានសម្របសម្រួល categories សម្រាប់ facts {updated_count}", "success")
    except Exception as e:
        flash(f"កំហុសក្នុងការសម្របសម្រួល categories: {e}", "danger")
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
                flash("បានបញ្ចប់ការវិនិច្ឆ័យ និងបានរក្សាទុកក្នុងប្រវត្តិ", "success")
            except Exception:
                flash("បានបញ្ចប់ការវិនិច្ឆ័យ ប៉ុន្តែមិនអាចរក្សាទុកក្នុងប្រវត្តិ", "warning")

            return render_template("infer.html", facts=active_facts, obs_conf=obs_conf,
                                 results=results, expanded_obs=expanded_obs)
            
        except Exception as e:
            flash(f"កំហុសក្នុងការសន្និដ្ឋាន: {str(e)}", "danger")
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
    flash("បានកំណត់ឡើងវិញនូវតម្លៃជឿជាក់ និងលទ្ធផលទាំងអស់", "success")
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
                processed_item["formatted_timestamp"] = "មិនស្គាល់ពេលវេលា"
            
            if processed_item.get("results"):
                sorted_results = sorted(processed_item["results"], key=lambda r: r.get("confidence", 0), reverse=True)
                if sorted_results:
                    top = sorted_results[0]
                    processed_item["top_conclusion"] = top.get("conclusion", "មិនស្គាល់")
                    confidence_value = top.get("confidence", 0)
                    confidence_value = max(0.0, min(1.0, float(confidence_value)))
                    processed_item["top_confidence"] = int(confidence_value * 100)
                else:
                    processed_item["top_conclusion"] = "គ្មានការសន្និដ្ឋាន"
                    processed_item["top_confidence"] = 0
            else:
                processed_item["top_conclusion"] = "គ្មានលទ្ធផលវិនិច្ឆ័យ"
                processed_item["top_confidence"] = 0
            
            processed_items.append(processed_item)

        return render_template("history_list.html", items=processed_items)
    
    except Exception as e:
        flash("កំហុសក្នុងការទាញយកប្រវត្តិ", "danger")
        return render_template("history_list.html", items=[])

@app.route("/history/<int:hid>")
@login_required
def history_detail(hid):
    items = get_history(current_user.id)
    item = next((x for x in items if x.get("id") == hid), None)
    if not item:
        flash("រកមិនឃើញធាតុប្រវត្តិ", "warning")
        return redirect(url_for("history_list"))
    return render_template("history_detail.html", item=item)

@app.route("/history/delete/<int:hid>", methods=["POST"])
@login_required
def delete_history(hid):
    try:
        delete_history_item(hid, current_user.id)
        flash(f"បានលុបធាតុប្រវត្តិ", "success")
    except Exception as e:
        flash(f"កំហុសក្នុងការលុបប្រវត្តិ: {str(e)}", "danger")
    
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
        
        # ទាញយកកំណត់ហេតុសម្អាត (ធាតុចុងក្រោយ 50)
        audit_logs = get_audit_logs(limit=50)
        
        # ដំណើរការកំណត់ហេតុសម្អាតដើម្បីដោះស្រាយ datetime
        for log in audit_logs:
            if log.get('created_at'):
                # ប្រសិនបើវាជាវត្ថុ datetime រួចហើយ ទុកវា
                if not isinstance(log['created_at'], str):
                    # បំលែង datetime ទៅជាខ្សែអក្សរប្រសិនបើចាំបាច់
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
        flash(f'កំហុសក្នុងការទាញយកផ្ទាំងគ្រប់គ្រងអ្នកគ្រប់គ្រង: {str(e)}', 'danger')
        return redirect(url_for('home'))

@app.route("/admin/users/<int:user_id>/update_role", methods=["POST"])
@admin_required
def admin_update_user_role(user_id):
    new_role = request.form.get("role")
    if new_role in ['admin', 'expert', 'user']:
        try:
            # ទាញយកអ្នកប្រើប្រាស់មុនពេលធ្វើបច្ចុប្បន្នភាព
            user = get_user(user_id)
            old_value = {'role': user['role']} if user else None
            
            # ធ្វើបច្ចុប្បន្នភាពតួនាទី
            success = update_user_role(user_id, new_role)
            
            if success:
                # កត់ត្រាព្រឹត្តិការណ៍សម្អាត
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
                flash(f"បានធ្វើបច្ចុប្បន្នភាពតួនាទីអ្នកប្រើប្រាស់ទៅ {new_role}", "success")
            else:
                flash("មិនអាចធ្វើបច្ចុប្បន្នភាពតួនាទីអ្នកប្រើប្រាស់", "danger")
        except Exception as e:
            flash(f"កំហុស: {str(e)}", "danger")
    else:
        flash("តួនាទីមិនត្រឹមត្រូវ", "danger")
    
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
        flash("ឈ្មោះអ្នកប្រើប្រាស់ និងពាក្យសម្ងាត់ត្រូវបំពេញ", "danger")
        return redirect(url_for('admin_users'))
    
    if password != confirm_password:
        flash("ពាក្យសម្ងាត់មិនដូចគ្នា", "danger")
        return redirect(url_for('admin_users'))
    
    if len(password) < 6:
        flash("ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ", "danger")
        return redirect(url_for('admin_users'))
    
    try:
        user_id = create_user(username, password, email, role)
        
        # កត់ត្រាព្រឹត្តិការណ៍សម្អាត
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
        
        flash(f"បានបង្កើតអ្នកប្រើប្រាស់ '{username}' ដោយជោគជ័យ", "success")
    except Exception as e:
        flash(f"មិនអាចបង្កើតអ្នកប្រើប្រាស់: {str(e)}", "danger")
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/toggle/<int:user_id>", methods=["POST"])
@admin_required
def admin_toggle_user_status(user_id):
    if user_id == current_user.id:
        flash("មិនអាចប្តូរស្ថានភាពផ្ទាល់ខ្លួន", "warning")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if user:
            new_status = not user['is_active']
            
            # Get old value
            old_value = {'is_active': user['is_active']}
            
            cursor.execute(
                "UPDATE users SET is_active = %s WHERE id = %s",
                (new_status, user_id)
            )
            
            conn.commit()
            
            # AUDIT LOGGING - FIXED
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
            
            status_text = "បានបើកដំណើរការ" if new_status else "បានបិទ"
            flash(f"បាន{status_text}អ្នកប្រើប្រាស់ដោយជោគជ័យ", "success")
        else:
            flash("រកមិនឃើញអ្នកប្រើប្រាស់", "warning")
            
    except Exception as e:
        flash(f"មិនអាចធ្វើបច្ចុប្បន្នភាពស្ថានភាពអ្នកប្រើប្រាស់: {str(e)}", "danger")
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
        flash("ត្រូវការ User ID", "danger")
        return redirect(url_for('admin_users'))
    
    if not username:
        flash("ត្រូវការឈ្មោះអ្នកប្រើប្រាស់", "danger")
        return redirect(url_for('admin_users'))
    
    if password and password != confirm_password:
        flash("ពាក្យសម្ងាត់មិនដូចគ្នា", "danger")
        return redirect(url_for('admin_users'))
    
    if password and len(password) < 6:
        flash("ពាក្យសម្ងាត់ត្រូវមានយ៉ាងតិច ៦ តួអក្សរ", "danger")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # ទាញយកទិន្នន័យអ្នកប្រើប្រាស់ចាស់សម្រាប់កំណត់ហេតុសម្អាត
        cursor.execute("SELECT username, email FROM users WHERE id = %s", (user_id,))
        old_user = cursor.fetchone()
        
        cursor.execute(
            "SELECT id FROM users WHERE username = %s AND id != %s",
            (username, user_id)
        )
        if cursor.fetchone():
            flash(f"ឈ្មោះអ្នកប្រើប្រាស់ '{username}' មានរួចហើយ", "danger")
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
        
        # កត់ត្រាព្រឹត្តិការណ៍សម្អាត
        old_value = {'username': old_user['username'], 'email': old_user['email']} if old_user else None
        new_value = {'username': username, 'email': email}
        if password:
            new_value['password'] = '******'  # កុំកត់ត្រាពាក្យសម្ងាត់ជាក់ស្តែង
        
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
        
        flash(f"បានធ្វើបច្ចុប្បន្នភាពអ្នកប្រើប្រាស់ '{username}' ដោយជោគជ័យ", "success")
        
    except Exception as e:
        flash(f"មិនអាចធ្វើបច្ចុប្បន្នភាពអ្នកប្រើប្រាស់: {str(e)}", "danger")
    finally:
        cursor.close()
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route("/admin/users/delete", methods=["POST"])
@admin_required
def admin_delete_user():
    user_id = request.form.get("user_id")
    
    if not user_id:
        flash("ត្រូវការ User ID", "danger")        
        return redirect(url_for('admin_users'))
    
    if int(user_id) == current_user.id:
        flash("មិនអាចលុបគណនីផ្ទាល់ខ្លួន", "warning")
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # ទាញយកទិន្នន័យអ្នកប្រើប្រាស់មុនពេលលុបសម្រាប់កំណត់ហេតុសម្អាត
        # ONLY get non-sensitive fields
        cursor.execute("SELECT id, username, email, role, is_active, created_at FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()    
        
        if not user:
            flash("រកមិនឃើញអ្នកប្រើប្រាស់", "warning")
            return redirect(url_for('admin_users'))
        
        # Clean user data for audit logging
        cleaned_user = dict(user)
        
        # Ensure all values are JSON serializable
        for key, value in cleaned_user.items():
            if isinstance(value, datetime):
                cleaned_user[key] = value.isoformat()
            elif value is None:
                cleaned_user[key] = None
        
        # លុបអ្នកប្រើប្រាស់
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        
        # កត់ត្រាព្រឹត្តិការណ៍សម្អាត
        log_audit(
            user_id=current_user.id,
            action='DELETE',
            table_name='users',
            record_id=user_id,
            old_value=cleaned_user,  # Use cleaned data
            new_value=None,
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        
        conn.commit()
        
        flash(f"បានលុបអ្នកប្រើប្រាស់ដោយជោគជ័យ", "success")
        
    except Exception as e:
        flash(f"មិនអាចលុបអ្នកប្រើប្រាស់: {str(e)}", "danger")
        print(f"Delete user error: {e}")  # For debugging
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
            return jsonify({"success": False, "error": "មិនមាន log IDs បានផ្តល់"})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # បំលែងបញ្ជីទៅជា tuple សម្រាប់ SQL IN clause
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
            # បំលែងទៅជាឯកសារ JSON
            response = jsonify(log)
            response.headers['Content-Disposition'] = f'attachment; filename=audit_log_{log_id}.json'
            return response
        else:
            flash("រកមិនឃើញកំណត់ហេតុ", "danger")
            return redirect(url_for('admin_users'))
    except Exception as e:
        flash(f"ការនាំចេញមិនបានសម្រេច: {str(e)}", "danger")
        return redirect(url_for('admin_users'))

@app.route("/admin/audit/export-batch")
@admin_required
def export_audit_logs_batch():
    try:
        log_ids = request.args.get('ids', '').split(',')
        if not log_ids or log_ids[0] == '':
            flash("មិនមានកំណត់ហេតុបានជ្រើសរើស", "warning")
            return redirect(url_for('admin_users'))
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        placeholders = ', '.join(['%s'] * len(log_ids))
        query = f"SELECT * FROM audit_log WHERE id IN ({placeholders}) ORDER BY created_at DESC"
        cursor.execute(query, tuple(log_ids))
        logs = cursor.fetchall()
        
        # បំលែងទៅជាឯកសារ JSON
        response = jsonify(logs)
        response.headers['Content-Disposition'] = f'attachment; filename=audit_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        return response
    except Exception as e:
        flash(f"ការនាំចេញមិនបានសម្រេច: {str(e)}", "danger")
        return redirect(url_for('admin_users'))
@app.route("/admin/audit/clear-all", methods=["POST"])
@admin_required
def clear_all_audit_logs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_log")
        conn.commit()
        return jsonify({"success": True, "deleted": cursor.rowcount})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})    
    

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
        "taxonomy_keys": list(taxonomy_data.keys())[:5] if taxonomy_data else "គ្មាន taxonomy"
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=os.getenv("FLASK_DEBUG") == "1")