from unittest.mock import Mock

from flask import url_for, redirect, request
from pytest import fixture

from role import USER, ADMIN

TEST_SUB = 'user-id'
TEST_ID = 'registration_id'
TEST_MAIL = 'test@mail.com'


def test_index_redirects_unauthorized_user_to_login(client):
    res = client.get('/')
    assert res.status_code == 302
    assert res.location == url_for('login', next='/', _external=True)


def test_unregistered_user_can_not_login(client):
    login_res = client.get('/login', follow_redirects=True)
    assert login_res.status_code == 403
    index_res = client.get('/')
    assert index_res.status_code != 200


def test_user_cannot_register_without_record(client):
    res = client.get(f'/register?id={TEST_ID}', follow_redirects=True)
    assert res.status_code == 404


def test_user_registration(client):
    from memeboard import RegistrationLink, User, Role

    add_registration_link(client, TEST_ID)
    res = client.get(f'/register?id={TEST_ID}', follow_redirects=True)
    assert not RegistrationLink.query.filter_by(id=TEST_ID).first()
    assert User.query.filter_by(id=TEST_SUB).first() == User(id=TEST_SUB, email=TEST_MAIL, roles=[Role(id=USER)])
    assert res.status_code == 200
    assert request.path == '/'


def test_user_redirected_to_index_after_login(client):
    add_user(client.db, TEST_SUB, TEST_MAIL)
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
        client.app = app
        yield client
    db.drop_all()


@fixture
def mock_oauth():
    oauth = Mock()
    oauth.google.authorize_redirect = Mock(side_effect=redirect)
    oauth.google.parse_id_token = Mock(return_value=dict(sub=TEST_SUB, email=TEST_MAIL))
    return oauth


def add_user(db, user_id, email, is_admin=False):
    from memeboard import Role, User

    role_slugs = [USER, ADMIN] if is_admin else [USER]
    roles = [Role(id=r) for r in role_slugs]
    user = User(id=user_id, email=email, roles=roles)
    db.session.add(user)
    db.session.commit()


def add_registration_link(client, registration_id):
    from memeboard import RegistrationLink

    with client.app.test_request_context():
        link = url_for('register', id=registration_id, _external=True)
    link_record = RegistrationLink(id=registration_id, link=link)
    client.db.session.add(link_record)
    client.db.session.commit()
