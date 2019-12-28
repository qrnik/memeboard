from authlib.integrations.flask_client import OAuth
from flask import Flask, url_for, redirect, abort
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix

import role
from config import configure

app = Flask(__name__)
configure(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
oauth = OAuth(app)
oauth.register(
    'google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
db = SQLAlchemy(app)
migrate = Migrate(app, db)


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


@app.route('/')
@login_required
def hello():
    return 'Hello World!'


@app.route('/login')
def login():
    redirect_uri = url_for('authorize', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully.'


@app.route('/authorize')
def authorize():
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)
    user_id = user_info['sub']
    user = load_user(user_id)
    if not user or not user.is_user():
        abort(401)
    login_user(user)
    return redirect('/')


class User(db.Model, UserMixin):
    id = db.Column(db.String(64), primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    roles = db.relationship('UserRole')

    def is_user(self):
        return role.USER in [r.role for r in self.roles]

    def is_admin(self):
        return role.ADMIN in [r.role for r in self.roles]


class UserRole(db.Model):
    user_id = db.Column(db.String(64), db.ForeignKey('user.id'), primary_key=True)
    role = db.Column(db.String(64), primary_key=True)
