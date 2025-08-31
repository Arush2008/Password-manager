from flask import Flask, Blueprint, render_template, request, redirect, url_for

views = Blueprint('views', __name__)

password_entries = {
    'Personal': [],
    'Work': [],
    'Finance': [],
    'Gaming': []
}

@views.route('/')
def index():
    return render_template('index.html')

@views.route('/vault', methods=['GET', 'POST'])
def vault():
    category = request.args.get('category', 'All Passwords')
    show_password_generator_popup = request.args.get('popup') == 'password-generator'
    show_new_entry_popup = request.args.get('popup') == 'add-new-entry'

    if request.method == 'POST':
        title = request.form.get('title')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        selected_category = request.form.get('category')  # This comes from the form
        
        entry = {
            'title': title,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'category': selected_category
        }
        
        if selected_category in password_entries:
            password_entries[selected_category].append(entry)
        
        return redirect(url_for('views.vault', category=selected_category))

    if category == 'All Passwords':
        current_passwords = []
        for cat_passwords in password_entries.values():
            current_passwords.extend(cat_passwords)
    else:
        current_passwords = password_entries.get(category, [])

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
        password_length=password_length,
        generated_password=generated_password,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols,
        passwords=current_passwords)

