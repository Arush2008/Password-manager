from flask import Flask, Blueprint, render_template, request, redirect, url_for
import sqlite3

views = Blueprint('views', __name__)

def get_db_connection():
    conn = sqlite3.connect("password_manager.db")
    conn.row_factory = sqlite3.Row

    conn.execute("""
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        site_name TEXT NOT NULL,
        site_username TEXT NOT NULL,
        site_password TEXT NOT NULL,
        url TEXT,
        notes TEXT
    )
    """)
    conn.commit()

    return conn

password_categories = {}

@views.route('/')
def index():
    return render_template('index.html')

@views.route('/vault', methods=['GET', 'POST'])
def vault():
    category = request.args.get('category', 'All Passwords')
    show_password_generator_popup = request.args.get('popup') == 'password-generator'
    show_new_entry_popup = request.args.get('popup') == 'add-new-entry'
    show_edit_entry_popup = request.args.get('popup') == 'edit-entry'
    edit_password_id = request.args.get('id')
    show_password = request.args.get('show_password') == 'true'

    edit_password_data = None
    if show_edit_entry_popup and edit_password_id:
        conn = get_db_connection()
        edit_password_data = conn.execute("SELECT * FROM passwords WHERE id = ?", (edit_password_id,)).fetchone()
        conn.close()

    if request.method == 'POST':
        title = request.form.get('title')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        selected_category = request.form.get('category')
        password_id = request.form.get('password_id')

        conn = get_db_connection()
        
        if password_id:
            conn.execute(
                "UPDATE passwords SET site_name = ?, site_username = ?, site_password = ?, url = ?, notes = ? WHERE id = ?",
                (title, username, password, url, notes, password_id)
            )
            password_categories[int(password_id)] = selected_category
        else: 
            cursor = conn.execute(
                "INSERT INTO passwords (site_name, site_username, site_password, url, notes) VALUES (?, ?, ?, ?, ?)",
                (title, username, password, url, notes)
            )
            password_id = cursor.lastrowid
            password_categories[password_id] = selected_category
        
        conn.commit()
        conn.close()

        return redirect(url_for('views.vault', category=selected_category))

    conn = get_db_connection()
    all_passwords = conn.execute("SELECT * FROM passwords").fetchall()
    conn.close()

    if category == "All Passwords":
        current_passwords = all_passwords
    else:
        current_passwords = []
        for password in all_passwords:
            if password_categories.get(password['id']) == category:
                current_passwords.append(password)

    password_length = 12
    generated_password = ""
    include_uppercase = True
    include_lowercase = True
    include_numbers = True
    include_symbols = True

    return render_template('vault.html', 
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
        passwords=current_passwords,
        password_categories=password_categories
    )

@views.route('/delete/<int:id>')
def delete_password(id):
    conn = get_db_connection()
    conn.execute("DELETE FROM passwords WHERE id = ?", (id,))
    conn.commit()
    conn.close()
    
    if id in password_categories:
        del password_categories[id]
    
    return redirect(url_for('views.vault', category='All Passwords'))