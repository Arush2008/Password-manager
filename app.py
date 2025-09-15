import os
from flask import Flask
from views import views

app = Flask(__name__)
app.secret_key = 'change-this-in-production'
app.register_blueprint(views, url_prefix='/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, port=port)
