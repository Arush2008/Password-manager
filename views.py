"""Views module for password manager Flask application."""

from flask import (
    Blueprint, render_template, request, redirect, url_for, jsonify, session
)
import sqlite3
import random
import string

views = Blueprint('views', __name__)


def get_db_connection():

    """Establish and return a database connection."""
    conn = sqlite3.connect("password_manager.db")
    conn.row_factory = sqlite3.Row

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_name TEXT NOT NULL,
            site_username TEXT NOT NULL,
            site_password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            category TEXT NOT NULL DEFAULT 'Personal'
        )
        """
    )
    conn.commit()

    cur = conn.execute("PRAGMA table_info(passwords)")
    cols = {row[1] for row in cur.fetchall()}
    if "category" not in cols:
        conn.execute(
            "ALTER TABLE passwords ADD COLUMN category TEXT NOT NULL "
            "DEFAULT 'Personal'"
        )
        conn.commit()

    return conn


def generate_password(length=12, include_uppercase=True,
                      include_lowercase=True, include_numbers=True,
                      include_symbols=True):
    """
    Generate a secure password based on specified criteria.

    Args:
        length (int): Length of the password (8-32 characters)
        include_uppercase (bool): Include uppercase letters (A-Z)
        include_lowercase (bool): Include lowercase letters (a-z)
        include_numbers (bool): Include numbers (0-9)
        include_symbols (bool): Include special characters (!@#$%^&*)

    Returns:
        str: Generated password
    """
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
    """Render the index page."""
    return render_template('index.html')


@views.route('/vault', methods=['GET', 'POST'])
def vault():
    """Handle vault page with password management and generator."""
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

    edit_password_data = None
    if show_edit_entry_popup and edit_password_id:
        conn = get_db_connection()
        edit_password_data = conn.execute(
            "SELECT * FROM passwords WHERE id = ?",
            (edit_password_id,)
        ).fetchone()
        conn.close()

    if request.method == 'POST':
        title = request.form.get('title')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        selected_category = request.form.get('category') or 'Personal'
        password_id = request.form.get('password_id')

        conn = get_db_connection()

        if password_id:
            conn.execute(
                (
                    "UPDATE passwords SET site_name = ?, site_username = ?, "
                    "site_password = ?, url = ?, notes = ?, category = ? "
                    "WHERE id = ?"
                ),
                (
                    title,
                    username,
                    password,
                    url,
                    notes,
                    selected_category,
                    password_id,
                ),
            )
        else:
            cursor = conn.execute(
                (
                    "INSERT INTO passwords (site_name, site_username, "
                    "site_password, url, notes, category) "
                    "VALUES (?, ?, ?, ?, ?, ?)"
                ),
                (title, username, password, url, notes, selected_category),
            )
            password_id = cursor.lastrowid

        conn.commit()
        conn.close()

        session['selected_category'] = selected_category
        return redirect(url_for('views.vault', category=selected_category))

    conn = get_db_connection()
    if category == "All Passwords":
        current_passwords = conn.execute(
            "SELECT * FROM passwords ORDER BY id DESC"
        ).fetchall()
    else:
        current_passwords = conn.execute(
            "SELECT * FROM passwords WHERE category = ? ORDER BY id DESC",
            (category,)
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
    """Delete a password entry by ID."""
    conn = get_db_connection()
    current_category = request.args.get(
        'category', session.get('selected_category', 'All Passwords')
    )
    session['selected_category'] = current_category

    conn.execute("DELETE FROM passwords WHERE id = ?", (id,))
    conn.commit()
    conn.close()

    return redirect(url_for('views.vault', category=current_category))


@views.route('/generate-password')
def generate_password_ajax():
    """AJAX endpoint for generating passwords dynamically."""
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
