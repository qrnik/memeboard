from pytest import fixture

from application import application


def test_index(client):
    res = client.get('/')
    assert res.data == b'Hello World!'


@fixture
def client():
    application.testing = True
    with application.test_client() as client:
        yield client
