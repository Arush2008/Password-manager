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
from werkzeug.security import generate_password_hash, check_password_hash

views = Blueprint('views', __name__)


def get_db_connection():
    """Establish and return a database connection."""
    conn = sqlite3.connect("password_manager.db")
    conn.row_factory = sqlite3.Row
    conn.commit()

    # This checks to ensure newer columns exist even if
    # the table was created by an older version of the app.
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
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
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
                values={'email': email, 'name': name}
            )
        hashed_pw = generate_password_hash(password)
        cursor = conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, hashed_pw)
        )
        conn.commit()
        session['user_id'] = cursor.lastrowid
        session.pop('master_verified', None)
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
        email = request.form.get('email')
        password = request.form.get('password')
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
        session['user_id'] = user['id']
        session.pop('master_verified', None)
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
        mp1 = request.form.get('master_password')
        mp2 = request.form.get('master_password_confirm')
        errors = {}
        if not mp1:
            errors.setdefault('master', {})[
                'master_password'
            ] = 'Please enter your master password'
        if not mp2:
            errors.setdefault('master', {})[
                'master_password_confirm'
            ] = 'Please confirm your master password'
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
        )
        if not entered:
            return render_template(
                'index.html',
                errors={'master_verify': {'master': 'Password is invalid'}},
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
        title = request.form.get('title')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        selected_category = request.form.get('category') or 'Personal'
        password_id = request.form.get('password_id')
        user_id = session.get('user_id')

        if password_id:
            # Update existing opetion in the passwords table
            conn.execute(
                (
                    "UPDATE passwords SET site_name = ?, site_username = ?, "
                    "site_password = ?, url = ?, notes = ?, category = ? "
                    "WHERE id = ? AND user_id = ?"
                ),
                (
                    title,
                    username,
                    password,
                    url,
                    notes,
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
                 title,
                 username,
                 password,
                 url,
                 notes,
                 selected_category),
            )
            password_id = cursor.lastrowid

        conn.commit()
        conn.close()
        # save selected category in session and go back to the vault
        session['selected_category'] = selected_category
        return redirect(url_for('views.vault', category=selected_category))

    # read and display password entries for the user and selected category
    user_id = session.get('user_id')
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
        show_password_generator_popup=show_password_generator_popup,
        show_new_entry_popup=show_new_entry_popup,
        show_edit_entry_popup=show_edit_entry_popup,
        edit_password_data=edit_password_data,
        edit_password_id=edit_password_id,
        show_password=show_password,
        password_length=password_length,
        generated_password=generated_password,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols,
        passwords=current_passwords
    )


@views.route('/delete/<int:id>')
def delete_password(id):
    """Delete a password entry using ID.

    Uses the user's current ID from the session so user can only
    delete their entries.
    After they delete an entry they are redirected back to the vault page.
    """
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
