from flask import Flask, Blueprint, render_template, request

views = Blueprint('views', __name__)

@views.route('/')
def index():
    return render_template('index.html')

@views.route('/vault')
def vault():
    category = request.args.get('category', 'All Passwords')
    show_password_generator_popup = request.args.get('popup') == 'password-generator'
    show_new_entry_popup = request.args.get('popup') == 'add-new-entry'

    # Default values for template variables (no actual generation)
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
        include_symbols=include_symbols)

