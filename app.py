"""Main Flask application module for password manager."""

from flask import Flask
from views import views

app = Flask(__name__)
app.secret_key = 'change-this-in-production'
app.register_blueprint(views, url_prefix='/')

if __name__ == '__main__':
    app.run(debug=True)
