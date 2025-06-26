from flask import Flask, Blueprint, render_template, request

views = Blueprint('views', __name__)

@views.route('/')
def index():
    return render_template('index.html')

@views.route('/vault')
def vault():
    category = request.args.get('category', 'all')
    return render_template('vault.html', category=category)
