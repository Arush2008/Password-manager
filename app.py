import os
from datetime import timedelta
from flask import Flask
from views import views

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'nI{4nB!Nk4ZMI3lSGcFbddrH7):>bB=8'
)
# Absolute 20-minute session lifetime (no sliding refresh)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)
# Do not refresh cookie on each request (absolute expiration)
app.config['SESSION_REFRESH_EACH_REQUEST'] = False
# Optional cookie hardening; consider enabling SECURE in production
app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
app.config.setdefault('SESSION_COOKIE_SECURE', False)  # set True behind HTTPS
app.register_blueprint(views, url_prefix='/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(debug=True, port=port)
