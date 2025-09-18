from flask import (
    Blueprint,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    session,
)
import sqlite3
import random
import string
import math
import re
from urllib.parse import urlparse
from werkzeug.security import generate_password_hash, check_password_hash

views = Blueprint('views', __name__)


@views.before_app_request
def enforce_idle_timeout():
    """Clear session after an absolute 20-minute window since login.
    No sliding refresh; once 20 minutes elapse, the session is cleared.
    """
    from datetime import datetime, timedelta
    # only track for authenticated sessions
    if 'user_id' in session:
        now = datetime.utcnow()
        started = session.get('start_time')
        try:
            started_dt = (
                datetime.fromisoformat(started)
                if isinstance(started, str) else None
            )
        except Exception:
            started_dt = None
        # default to 20 minutes if not resolvable from app config
        timeout = timedelta(minutes=20)
        try:
            # get from current_app config if available
            from flask import current_app
            timeout = current_app.config.get(
                'PERMANENT_SESSION_LIFETIME', timeout
            )
        except Exception:
            pass

        if started_dt and (now - started_dt) > timeout:
            session.clear()
            # no redirect; route handlers will see cleared session


def get_db_connection():
    """Establish and return a database connection."""
    conn = sqlite3.connect("password_manager.db")
    conn.row_factory = sqlite3.Row
    conn.commit()

    # Ensure core tables exist
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT,
            password_hash TEXT NOT NULL,
            master_password_hash TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            site_name TEXT NOT NULL,
            site_username TEXT,
            site_password TEXT,
            url TEXT,
            notes TEXT,
            category TEXT DEFAULT 'Personal',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
        """
    )
    conn.commit()

    # Ensure categories table exists
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            UNIQUE(user_id, name)
        )
        """
    )
    conn.commit()

    # This checks to ensure newer columns exist even if
    # the table was created by an older version.
    cur = conn.execute("PRAGMA table_info(passwords)")
    cols = {row[1] for row in cur.fetchall()}
    if "category" not in cols:
        conn.execute(
            "ALTER TABLE passwords ADD COLUMN category TEXT NOT NULL "
            "DEFAULT 'Personal'"
        )
        conn.commit()
    if "user_id" not in cols:
        conn.execute(
            "ALTER TABLE passwords ADD COLUMN user_id "
            "INTEGER NOT NULL DEFAULT 1"
        )
        conn.commit()
    # Ensure 'name' column exists on users table for older schemas
    cur = conn.execute("PRAGMA table_info(users)")
    ucols = {row[1] for row in cur.fetchall()}
    if "name" not in ucols:
        conn.execute("ALTER TABLE users ADD COLUMN name TEXT")
        conn.commit()
    return conn


def generate_password(length=12, include_uppercase=True,
                      include_lowercase=True, include_numbers=True,
                      include_symbols=True):
    length = max(8, min(32, length))

    characters = ""

    if include_uppercase:
        characters += string.ascii_uppercase
    if include_lowercase:
        characters += string.ascii_lowercase
    if include_numbers:
        characters += string.digits
    if include_symbols:
        characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not characters:
        characters = string.ascii_lowercase

    password = []

    # At least one character from each selected category
    if include_uppercase and string.ascii_uppercase:
        password.append(random.choice(string.ascii_uppercase))
    if include_lowercase and string.ascii_lowercase:
        password.append(random.choice(string.ascii_lowercase))
    if include_numbers and string.digits:
        password.append(random.choice(string.digits))
    if include_symbols:
        password.append(random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    for _ in range(length - len(password)):
        password.append(random.choice(characters))

    random.shuffle(password)

    return ''.join(password)


def estimate_password_strength(pw: str):
    """Return a simple strength estimate for a password.
    Provides: score 0..4, label, entropy (bits), and naive offline crack time.
    The model is heuristic: character set size from used classes and length.
    """
    if not pw:
        return {
            'score': 0,
            'label': 'Very Weak',
            'entropy_bits': 0.0,
            'crack_time_display': 'instant'
        }

    # Determine character set size based on classes present
    charset = 0
    has_lower = any('a' <= c <= 'z' for c in pw)
    has_upper = any('A' <= c <= 'Z' for c in pw)
    has_digit = any('0' <= c <= '9' for c in pw)
    specials = "!@#$%^&*()_+-=[]{}|;:,.<>?" + "\"'`~\\/"
    has_symbol = any(c in specials for c in pw)
    if has_lower:
        charset += 26
    if has_upper:
        charset += 26
    if has_digit:
        charset += 10
    if has_symbol:
        # count a typical set
        charset += 33
    # Fallback minimal set if something unexpected
    if charset == 0:
        charset = 26

    length = len(pw)
    # Entropy approximation: length * log2(charset)
    entropy = length * (math.log(charset, 2))

    # Very rough score mapping by entropy and some common weakness checks
    score = 0
    if length >= 8:
        score += 1
    if sum([has_lower, has_upper, has_digit, has_symbol]) >= 2:
        score += 1
    if entropy >= 45:
        score += 1
    if (
        entropy >= 60 and
        sum([has_lower, has_upper, has_digit, has_symbol]) >= 3 and
        length >= 12
    ):
        score += 1
    score = max(0, min(4, score))

    labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong']

    # Crack time estimate (naive): tries/second for offline fast hashing
    # Assume 1e10 guesses/sec for GPU brute force of weak hashes.
    # Using log scale to avoid huge ints
    log_guesses = length * math.log10(charset)
    guesses_per_sec = 1e10
    seconds = 10 ** log_guesses / guesses_per_sec if charset > 0 else 0
    if not math.isfinite(seconds):
        seconds = 1e50

    def fmt_time(s: float) -> str:
        if s < 1:
            return 'instant'
        mins = s / 60
        hours = mins / 60
        days = hours / 24
        years = days / 365
        if s < 60:
            return f"{s:.0f} sec"
        if mins < 60:
            return f"{mins:.0f} min"
        if hours < 48:
            return f"{hours:.0f} hr"
        if days < 3650:
            return f"{days:.0f} days"
        if years < 1e9:
            return f"{years:.1f} years"
        return "> billions of years"

    return {
        'score': int(score),
        'label': labels[int(score)],
        'entropy_bits': round(entropy, 1),
        'crack_time_display': fmt_time(seconds),
    }


# ---------------------- Validation helpers ----------------------
def _clean(s: str) -> str:
    return (s or '').strip()


def _valid_email(email: str) -> bool:
    email = _clean(email).lower()
    # simple RFC-ish email check
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email))


def _valid_nonempty(text: str, min_len: int = 1, max_len: int = 255) -> bool:
    t = _clean(text)
    return min_len <= len(t) <= max_len


def _valid_password(
    pw: str,
    min_len: int = 8,
    max_len: int = 128,
    no_spaces: bool = False,
) -> bool:
    """Validate password length and optional whitespace restriction.
    - Trims outer whitespace for minimum length check to avoid spaces-only.
    - When no_spaces is True, rejects any whitespace anywhere in the string.
    """
    s = pw or ''
    if no_spaces and any(ch.isspace() for ch in s):
        return False
    t = _clean(s)
    return len(t) >= min_len and len(s) <= max_len


def _valid_url(u: str) -> bool:
    if not u:
        return True
    u = _clean(u)
    if not u:
        return True
    try:
        parsed = urlparse(u)
        return parsed.scheme in ('http', 'https') and bool(parsed.netloc)
    except Exception:
        return False


@views.route('/password-strength', methods=['POST'])
def password_strength_api():
    """AJAX endpoint to evaluate password strength.
    Requires authenticated session.
    """
    if 'user_id' not in session:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    pw = (data.get('password') or '').strip()
    result = estimate_password_strength(pw)
    return jsonify({'ok': True, **result})


@views.route('/')
def index():
    return render_template('ruth.html', view='signup')


@views.route('/signup', methods=['GET', 'POST'])
def signup():
    """Signup page with real email check.
    User must provide email and password to register. If the email already
    exists an inline error is shown. On success the user is auto-logged in and
    redirected to the master password setup page.
    """
    if request.method == 'POST':
        email = (request.form.get('email') or '').lower()
        password = request.form.get('password') or ''
        name = request.form.get('name') or ''
        errors = {'signup': {}}
        values = {'email': email, 'name': name}

        # Server-side validation
        if not _valid_nonempty(name, 1, 50):
            errors['signup']['name'] = (
                'Please enter your name (max 50 characters)'
            )
        if not _valid_email(email):
            errors['signup']['email'] = 'Please enter a valid email address'
        if not _valid_password(password, 8, 128, no_spaces=True):
            errors['signup']['password'] = (
                'Password must be at least 8 characters and must not '
                'contain spaces'
            )
        if errors['signup']:
            return render_template(
                'ruth.html', view='signup', errors=errors, values=values
            )
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        if user:
            # Show inline error under email field
            conn.close()
            return render_template(
                'ruth.html',
                view='signup',
                errors={'signup': {'email': 'Email already exists'}},
                values=values
            )
        hashed_pw = generate_password_hash(password)
        cursor = conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
            (email, name, hashed_pw)
        )
        conn.commit()
        session.permanent = True
        session['user_id'] = cursor.lastrowid
        session['email'] = email
        session['name'] = name
        session.pop('master_verified', None)
        # absolute timer start
        from datetime import datetime
        session['start_time'] = datetime.utcnow().isoformat()
        conn.close()
        return redirect(url_for('views.master'))
    return render_template('ruth.html', view='signup')


@views.route('/login', methods=['GET', 'POST'])
def login():
    """LLogin page with real authantications.

    user must provide email and password to login. If either is wrong
    an inline error is shown. On success the user is redirected to either
    the master password setup or the master password verification page.
    """
    if request.method == 'POST':
        email = (request.form.get('email') or '').lower()
        password = request.form.get('password') or ''
        # Basic server-side validation for tampering
        base_errors = {}
        if not _valid_email(email):
            base_errors['email'] = 'Please enter a valid email address'
        if not _valid_nonempty(password, 1, 1024):
            base_errors['password'] = 'Please enter your password'
        if base_errors:
            return render_template(
                'ruth.html',
                view='login',
                errors={'login': base_errors},
                values={'email': email}
            )
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()
        if not user:
            conn.close()
            return render_template(
                'ruth.html',
                view='login',
                errors={'login': {'email': 'Invalid email address'}},
                values={'email': email}
            )
        if not check_password_hash(user['password_hash'], password):
            conn.close()
            return render_template(
                'ruth.html',
                view='login',
                errors={'login': {'password': 'Password is invalid'}},
                values={'email': email}
            )
        conn.close()
        session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        try:
            session['name'] = user['name']
        except Exception:
            session['name'] = session.get('name')
        session.pop('master_verified', None)
        from datetime import datetime
        session['start_time'] = datetime.utcnow().isoformat()
        if not user['master_password_hash']:
            return redirect(url_for('views.master'))
        return redirect(url_for('views.master_verify'))
    return render_template('ruth.html', view='login')


@views.route('/master', methods=['GET', 'POST'])
def master():
    """
    Master password creation page.
    User must type twice, hashes and saves.
    """
    # user must be logged in to set a master password.
    if 'user_id' not in session:
        return redirect(url_for('views.login'))
    if request.method == 'POST':
        # needs both passwords to match in order to move forward.
        mp1 = request.form.get('master_password') or ''
        mp2 = request.form.get('master_password_confirm') or ''
        errors = {}
        if not _valid_password(mp1, 8, 128, no_spaces=True):
            errors.setdefault('master', {})[
                'master_password'
            ] = (
                'Master password must be at least 8 characters and must not '
                'contain spaces'
            )
        if not _valid_password(mp2, 8, 128, no_spaces=True):
            errors.setdefault('master', {})[
                'master_password_confirm'
            ] = (
                'Please confirm your master password (min 8 characters, '
                'no spaces)'
            )
        if mp1 and mp2 and mp1 != mp2:
            errors.setdefault('master', {})[
                'master_password_confirm'
            ] = 'Passwords do not match'
        if errors:
            return render_template('ruth.html', view='master', errors=errors)
        conn = get_db_connection()
        # It will store the passwords in hash form instead of normal password
        conn.execute(
            "UPDATE users SET master_password_hash = ? WHERE id = ?",
            (generate_password_hash(mp1), session['user_id'])
        )
        conn.commit()
        conn.close()
        session['master_verified'] = True
        return redirect(url_for('views.vault'))
    return render_template('ruth.html', view='master')


@views.route('/master-verify', methods=['GET', 'POST'])
def master_verify():
    """ask the user for thier master password to unlock the vault.
    If they are successful to write the correct password they will be
    redirected to the vault.
    """
    if 'user_id' not in session:
        return redirect(url_for('views.login'))

    if request.method == 'POST':
        entered = (
            request.form.get('master') or
            request.form.get('master_password')
        ) or ''
        if not _valid_nonempty(entered, 1, 1024):
            return render_template(
                'index.html',
                errors={'master_verify': {
                    'master': 'Please enter your master password'
                }},
            )
        conn = get_db_connection()
        user = conn.execute(
            "SELECT master_password_hash FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        conn.close()
        if not user or not user['master_password_hash']:
            return redirect(url_for('views.master'))
        if not check_password_hash(user['master_password_hash'], entered):
            return render_template(
                'index.html',
                errors={'master_verify': {'master': 'Password is invalid'}},
            )
        session['master_verified'] = True
        return redirect(url_for('views.vault'))

    return render_template('index.html')


@views.route('/logout')
def logout():
    """Clear the session and redirect to login."""
    session.clear()
    return redirect(url_for('views.login'))


@views.route('/vault', methods=['GET', 'POST'])
def vault():
    """
    Handle vault page with password management and generator.
    Requires login.
    """
    if 'user_id' not in session:
        return redirect(url_for('views.login'))
    conn = get_db_connection()
    # If the user has a master password then they are required verification
    user = conn.execute(
        "SELECT master_password_hash FROM users WHERE id = ?",
        (session['user_id'],)
    ).fetchone()
    if (
        user and user['master_password_hash'] and
        not session.get('master_verified')
    ):
        conn.close()
        return redirect(url_for('views.master_verify'))

    # Load user categories (built-in defaults + custom)
    user_id = session.get('user_id')
    # Email and display name for profile dropdown
    user_email = session.get('email')
    user_name = session.get('name')
    if not user_email:
        # fallback lookup
        row = conn.execute(
            "SELECT email, name FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
        if row:
            user_email = row['email']
            user_name = row['name'] if 'name' in row.keys() else None
            session['email'] = user_email
            if user_name:
                session['name'] = user_name

    def _display_name_from_email(email: str) -> str:
        if not email:
            return 'User'
        local = email.split('@')[0]
        for ch in ['.', '_', '-']:
            local = local.replace(ch, ' ')
        return ' '.join(w.capitalize() for w in local.split()) or 'User'
    display_name = (
        (user_name or '').strip() or _display_name_from_email(user_email)
    )
    # ensure default categories exist in UI, not necessarily in DB
    default_categories = [
        'All Passwords', 'Personal', 'Work', 'Finance', 'Gaming'
    ]
    user_categories = conn.execute(
        "SELECT name FROM categories WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()
    custom_categories = [row['name'] for row in user_categories]

    # Track currently selected category saved in the session
    if 'category' in request.args:
        category = request.args.get('category', 'All Passwords')
        session['selected_category'] = category
    else:
        category = session.get('selected_category', 'All Passwords')
    popup_type = request.args.get('popup')
    show_password_generator_popup = popup_type == 'password-generator'
    show_new_entry_popup = popup_type == 'add-new-entry'
    show_edit_entry_popup = popup_type == 'edit-entry'
    show_add_category_popup = popup_type == 'add-category'
    show_security_check_popup = popup_type == 'security-check'
    edit_password_id = request.args.get('id')
    show_password = request.args.get('show_password') == 'true'

    password_length = int(request.args.get('length', 12))
    include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    include_lowercase = request.args.get('lowercase', 'true').lower() == 'true'
    include_numbers = request.args.get('numbers', 'true').lower() == 'true'
    include_symbols = request.args.get('symbols', 'true').lower() == 'true'

    # Ensure at least one option is selected
    if not any([include_uppercase, include_lowercase,
                include_numbers, include_symbols]):
        include_uppercase = True
        include_lowercase = True
        include_numbers = True
        include_symbols = True

    password_length = max(8, min(32, password_length))

    # Generate password when popup is shown in the page
    generated_password = ""
    if show_password_generator_popup:
        generated_password = generate_password(
            length=password_length,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols
        )

    # while editing load the existing data to the form
    edit_password_data = None
    if show_edit_entry_popup and edit_password_id:
        edit_password_data = conn.execute(
            "SELECT * FROM passwords WHERE id = ?",
            (edit_password_id,)
        ).fetchone()

    # Handle form submission for adding or editing a password entry
    if request.method == 'POST':
        title = request.form.get('title') or ''
        username = request.form.get('username') or ''
        password = request.form.get('password') or ''
        url = request.form.get('url') or ''
        notes = request.form.get('notes') or ''
        selected_category = request.form.get('category') or 'Personal'
        password_id = request.form.get('password_id')
        user_id = session.get('user_id')

        # Validate category against known lists
        allowed_categories = (
            set(['Personal', 'Work', 'Finance', 'Gaming']) |
            set(custom_categories)
        )
        if selected_category not in allowed_categories:
            selected_category = 'Personal'

        verrors = {'vault': {}}
        # Validate fields (server-side, to prevent client tampering)
        if not _valid_nonempty(title, 1, 50):
            verrors['vault']['title'] = (
                'Enter a website/app name (max 50 characters)'
            )
        if not _valid_nonempty(username, 1, 50):
            verrors['vault']['username'] = (
                'Enter a username/email (max 50 characters)'
            )
        if not _valid_password(password, 8, 256, no_spaces=True):
            verrors['vault']['password'] = (
                'Password must be at least 8 characters and must not '
                'contain spaces'
            )
        if url and (len(url) > 2000 or not _valid_url(url)):
            verrors['vault']['url'] = (
                'Enter a valid URL'
            )
        if notes and len(_clean(notes)) > 100:
            verrors['vault']['notes'] = 'Notes must be 100 characters or fewer'

        # If validation fails, re-render with popup and errors
        if verrors['vault']:
            # Prepare values to refill form
            form_values = {
                'title': title,
                'username': username,
                'password': password,
                'url': _clean(url),
                'notes': _clean(notes),
                'category': selected_category,
            }
            # Need passwords list to render the page
            if category == "All Passwords":
                current_passwords = conn.execute(
                    (
                        "SELECT * FROM passwords WHERE user_id = ? "
                        "ORDER BY id DESC"
                    ),
                    (user_id,)
                ).fetchall()
            else:
                current_passwords = conn.execute(
                    (
                        "SELECT * FROM passwords WHERE user_id = ? "
                        "AND category = ? ORDER BY id DESC"
                    ),
                    (user_id, category)
                ).fetchall()

            if password_id:
                # Editing existing entry; keep the popup open
                edit_password_data = {
                    'id': password_id,
                    'site_name': title,
                    'site_username': username,
                    'site_password': password,
                    'url': _clean(url) or '',
                    'notes': _clean(notes) or '',
                    'category': selected_category,
                }
                conn.close()
                return render_template(
                    'vault.html',
                    category=category,
                    default_categories=default_categories,
                    custom_categories=custom_categories,
                    show_password_generator_popup=False,
                    show_new_entry_popup=False,
                    show_edit_entry_popup=True,
                    show_add_category_popup=False,
                    show_security_check_popup=False,
                    edit_password_data=edit_password_data,
                    edit_password_id=password_id,
                    show_password=False,
                    password_length=password_length,
                    generated_password='',
                    include_uppercase=include_uppercase,
                    include_lowercase=include_lowercase,
                    include_numbers=include_numbers,
                    include_symbols=include_symbols,
                    passwords=current_passwords,
                    user_email=user_email,
                    display_name=display_name,
                    errors=verrors,
                    form_values=form_values,
                )
            else:
                conn.close()
                return render_template(
                    'vault.html',
                    category=category,
                    default_categories=default_categories,
                    custom_categories=custom_categories,
                    show_password_generator_popup=False,
                    show_new_entry_popup=True,
                    show_edit_entry_popup=False,
                    show_add_category_popup=False,
                    show_security_check_popup=False,
                    edit_password_data=None,
                    edit_password_id=None,
                    show_password=False,
                    password_length=password_length,
                    generated_password='',
                    include_uppercase=include_uppercase,
                    include_lowercase=include_lowercase,
                    include_numbers=include_numbers,
                    include_symbols=include_symbols,
                    passwords=current_passwords,
                    user_email=user_email,
                    display_name=display_name,
                    errors=verrors,
                    form_values=form_values,
                )

        # Passed validation: persist
        title_db = _clean(title)
        username_db = _clean(username)
        url_db = _clean(url)
        notes_db = _clean(notes)

        if password_id:
            # Update existing option in the passwords table (scoped by user)
            conn.execute(
                (
                    "UPDATE passwords SET site_name = ?, site_username = ?, "
                    "site_password = ?, url = ?, notes = ?, category = ? "
                    "WHERE id = ? AND user_id = ?"
                ),
                (
                    title_db,
                    username_db,
                    password,
                    url_db,
                    notes_db,
                    selected_category,
                    password_id,
                    user_id,
                ),
            )
        else:
            # Create a new option in the passwords table
            cursor = conn.execute(
                (
                    "INSERT INTO passwords (user_id, site_name, site_username,"
                    "site_password, url, notes, category) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)"
                ),
                (user_id,
                 title_db,
                 username_db,
                 password,
                 url_db,
                 notes_db,
                 selected_category),
            )
            password_id = cursor.lastrowid

        conn.commit()
        conn.close()
        # save selected category in session and go back to the vault
        session['selected_category'] = selected_category
        return redirect(url_for('views.vault', category=selected_category))

    # read and display password entries for the user and selected category
    if category == "All Passwords":
        current_passwords = conn.execute(
            "SELECT * FROM passwords WHERE user_id = ? ORDER BY id DESC",
            (user_id,)
        ).fetchall()
    else:
        current_passwords = conn.execute(
            "SELECT * FROM passwords "
            "WHERE user_id = ? AND category = ? ORDER BY id DESC",
            (user_id, category)
        ).fetchall()
    conn.close()

    return render_template(
        'vault.html',
        category=category,
        default_categories=default_categories,
        custom_categories=custom_categories,
        show_password_generator_popup=show_password_generator_popup,
        show_new_entry_popup=show_new_entry_popup,
        show_edit_entry_popup=show_edit_entry_popup,
        show_add_category_popup=show_add_category_popup,
        show_security_check_popup=show_security_check_popup,
        edit_password_data=edit_password_data,
        edit_password_id=edit_password_id,
        show_password=show_password,
        password_length=password_length,
        generated_password=generated_password,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols,
        passwords=current_passwords,
        user_email=user_email,
        display_name=display_name
    )


@views.route('/categories', methods=['GET'])
def list_categories():
    if 'user_id' not in session:
        return redirect(url_for('views.login'))
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT name FROM categories WHERE user_id = ? ORDER BY name ASC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return jsonify({'categories': [r['name'] for r in rows]})


@views.route('/categories', methods=['POST'])
def add_category():
    if 'user_id' not in session:
        return redirect(url_for('views.login'))
    name = (request.form.get('name') or '').strip()
    if not name:
        return jsonify({'ok': False, 'error': 'Category name required'}), 400
    if name in ['All Passwords']:
        return jsonify({'ok': False, 'error': 'Reserved category name'}), 400
    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO categories (user_id, name) VALUES (?, ?)",
            (session['user_id'], name)
        )
        conn.commit()
    finally:
        conn.close()
    # Also set as selected to land on it after add
    session['selected_category'] = name
    return jsonify({'ok': True, 'name': name})


@views.route('/delete/<int:id>')
def delete_password(id):
    """Delete a password entry using ID.

    Uses the user's current ID from the session so user can only
    delete their entries.
    After they delete an entry they are redirected back to the vault page.
    """
    # Require login
    if 'user_id' not in session:
        return redirect(url_for('views.login'))

    conn = get_db_connection()
    current_category = request.args.get(
        'category', session.get('selected_category', 'All Passwords')
    )
    session['selected_category'] = current_category

    user_id = session.get('user_id')
    conn.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?",
                 (id, user_id))
    conn.commit()
    conn.close()

    return redirect(url_for('views.vault', category=current_category))


@views.route('/generate-password')
def generate_password_ajax():
    """using AJAX to generate password live on the vault page.
    The codes calls the generated_password function
    with the selected options and length
    and returns a JSON response with the new randomly generated password.
    """
    # redirect to login if not logged in
    if 'user_id' not in session:
        return redirect(url_for('views.login'))

    length = int(request.args.get('length', 12))
    include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
    include_lowercase = request.args.get('lowercase', 'true').lower() == 'true'
    include_numbers = request.args.get('numbers', 'true').lower() == 'true'
    include_symbols = request.args.get('symbols', 'true').lower() == 'true'

    password = generate_password(
        length=length,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols
    )

    return jsonify({'password': password})
