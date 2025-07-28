from flask import Flask, Blueprint, render_template, request
import random
import string

views = Blueprint('views', __name__)

def generate_password(length=12, include_uppercase=True, include_lowercase=True, include_numbers=True, include_symbols=True):
    """Generate a random password with the specified options"""
    charset = ""
    
    if include_lowercase:
        charset += string.ascii_lowercase
    if include_uppercase:
        charset += string.ascii_uppercase
    if include_numbers:
        charset += string.digits
    if include_symbols:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    if not charset:
        charset = string.ascii_letters  # Fallback to letters if nothing selected
    
    return ''.join(random.choice(charset) for _ in range(length))

@views.route('/')
def index():
    return render_template('index.html')

@views.route('/vault')
def vault():
    category = request.args.get('category', 'All Passwords')
    show_popup = request.args.get('popup') == 'password-generator'
    
    # Handle password length
    password_length = int(request.args.get('length', 12))
    password_length = max(8, min(32, password_length))  # Ensure within bounds
    
    # Handle password options
    include_uppercase = request.args.get('uppercase', 'true') == 'true'
    include_lowercase = request.args.get('lowercase', 'true') == 'true'
    include_numbers = request.args.get('numbers', 'true') == 'true'
    include_symbols = request.args.get('symbols', 'true') == 'true'
    
    # Generate password if popup is shown
    generated_password = ""
    if show_popup:
        generated_password = generate_password(
            length=password_length,
            include_uppercase=include_uppercase,
            include_lowercase=include_lowercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols
        )
    
    return render_template('vault.html', 
        category=category, 
        show_popup=show_popup,
        password_length=password_length,
        generated_password=generated_password,
        include_uppercase=include_uppercase,
        include_lowercase=include_lowercase,
        include_numbers=include_numbers,
        include_symbols=include_symbols)

