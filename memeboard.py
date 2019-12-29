from authlib.integrations.flask_client import OAuth
from flask import Flask, url_for, redirect, abort, request, g, session
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, login_user, UserMixin, login_required, logout_user, current_user
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix

import role
from config import configure

app = Flask(__name__)
configure(app)

# Support proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Configure OpenID Connect auth
oauth = OAuth(app)
oauth.register(
    'google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'}
)

# Configure login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Configure database
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
    session['next'] = request.args.get('next') or '/'
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
    if not user or not user.is_user:
        abort(403)
    login_user(user)
    next_uri = session['next'] or '/'
    return redirect(next_uri)


roles = db.Table(
    'roles',
    db.Column('user_id', db.String(64), db.ForeignKey('user.id'), primary_key=True),
    db.Column('role_id', db.String(64), db.ForeignKey('role.id'), primary_key=True)
)


class User(db.Model, UserMixin):
    id = db.Column(db.String(64), primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    roles = db.relationship('Role', secondary=roles, backref='users')

    @property
    def is_user(self):
        return role.USER in [r.id for r in self.roles]

    @property
    def is_admin(self):
        return role.ADMIN in [r.id for r in self.roles]

    def __str__(self):
        return self.email


class Role(db.Model):
    id = db.Column(db.String(64), primary_key=True)

    def __str__(self):
        return self.id


class SecuredAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_anonymous:
            return redirect(url_for('login', next=request.url))
        else:
            abort(403)


class SecuredModelView(ModelView):
    column_display_pk = True

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        if current_user.is_anonymous:
            return redirect(url_for('login', next=request.url))
        else:
            abort(403)


# Configure admin view
admin = Admin(app, name='Memeboard Admin', template_mode='bootstrap3', index_view=SecuredAdminIndexView())
admin.add_view(SecuredModelView(Role, db.session))
admin.add_view(SecuredModelView(User, db.session))
