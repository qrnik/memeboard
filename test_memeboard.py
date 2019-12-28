from unittest.mock import Mock

from flask import url_for, redirect, request
from pytest import fixture

from role import USER, ADMIN

TEST_SUB = 'user-id'


def test_index_redirects_unauthorized_user_to_login(client):
    res = client.get('/')
    assert res.status_code == 302
    assert res.location == url_for('login', next='/', _external=True)


def test_unregistered_user_can_not_login(client):
    login_res = client.get('/login', follow_redirects=True)
    assert login_res.status_code == 401
    index_res = client.get('/')
    assert index_res.status_code != 200


def test_user_redirected_to_index_after_login(client):
    add_user(client.db, TEST_SUB, 'test@mail.com')
    res = client.get('/login', follow_redirects=True)
    assert res.status_code == 200
    assert request.path == '/'


@fixture
def client(mock_oauth, monkeypatch):
    monkeypatch.setenv('FLASK_ENV', 'test')

    import memeboard
    from memeboard import app, db

    app.testing = True
    db.create_all()
    monkeypatch.setattr(memeboard, 'oauth', mock_oauth)
    with app.test_client() as client:
        client.db = db
        yield client
    db.drop_all()


@fixture
def mock_oauth():
    oauth = Mock()
    oauth.google.authorize_redirect = Mock(side_effect=redirect)
    oauth.google.parse_id_token = Mock(return_value={'sub': TEST_SUB})
    return oauth


def add_user(db, user_id, email, is_admin=False):
    from memeboard import UserRole, User

    roles = [USER, ADMIN] if is_admin else [USER]
    user_roles = [UserRole(role=r) for r in roles]
    user = User(id=user_id, email=email, roles=user_roles)
    db.session.add(user)
    db.session.commit()
