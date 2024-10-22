import base64
from http import HTTPStatus
import pytest
from faker import Faker
from fastapi.testclient import TestClient
from lecture_4.demo_service.api.contracts import UserResponse
from lecture_4.demo_service.api.main import create_app

faker = Faker()
app = create_app()

@pytest.fixture
def client():
    """
    Fixture that creates and returns a TestClient for FastAPI app.
    Used to send test requests to the API.
    """
    with TestClient(app) as client:
        yield client


@pytest.fixture()
def user(password, client):
    """
    Fixture that registers a test user and returns the user details.
    
    Args:
        password: The password used for registration.
        client: The test client used to send API requests.
    
    Returns:
        UserResponse: A response object with user details (uid, username, name, birthdate, role).
    """
    username = 'test_user_1'
    name = 'test_name_1'
    birthdate = str(faker.date_time().isoformat())

    resp = client.post('/user-register', json={
        'username': username,
        'name': name,
        'birthdate': birthdate,
        'password': password,
    })
    json = resp.json()
    return UserResponse(uid=json['uid'], username=username, name=name, birthdate=birthdate, role=json['role'])


@pytest.fixture()
def password():
    """
    Fixture that returns a default test password.
    
    Returns:
        str: A predefined test password.
    """
    return "secret_password_12345"


@pytest.fixture()
def admin_creds():
    """
    Fixture that returns encoded admin credentials for authorization.
    
    Returns:
        str: Base64-encoded admin credentials.
    """
    return base64.b64encode(f"admin:superSecretAdminPassword123".encode("ascii")).decode("utf-8")


def test_register_user(password, user, client):
    """
    Test the user registration API endpoint. Ensures that user is correctly registered.
    
    Args:
        password: The password used for registration.
        user: The registered test user.
        client: The test client used to send API requests.
    """
    username = 'test_user'
    name = 'test_name'
    birthdate = str(faker.date_time().isoformat())

    resp = client.post('/user-register', json={
        'username': username,
        'name': name,
        'birthdate': birthdate,
        'password': password,
    })
    json = resp.json()

    assert resp.status_code == HTTPStatus.OK
    assert json['username'] == username
    assert json['birthdate'] == birthdate
    assert json['name'] == name


def test_register_user_with_username_already_taken(client, password, user):
    """
    Test that attempting to register a user with an already taken username results in a BAD_REQUEST error.
    
    Args:
        client: The test client used to send API requests.
        password: The password used for registration.
        user: The registered test user.
    """
    resp = client.post('/user-register', json={
        'username': user.username,
        'name': user.name,
        'birthdate': str(user.birthdate),
        'password': password,
    })

    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_register_with_invalid_password(client):
    """
    Test that attempting to register a user with an invalid password results in a BAD_REQUEST error.
    
    Args:
        client: The test client used to send API requests.
    """
    resp = client.post('/user-register', json={
        'username': 'user1',
        'name': 'user1',
        'birthdate': str(faker.date_time().isoformat()),
        'password': '1',
    })

    assert resp.status_code == HTTPStatus.BAD_REQUEST


def test_get_unknown_user(password, admin_creds, client):
    """
    Test that attempting to retrieve a non-existing user results in a NOT_FOUND error.
    
    Args:
        password: The password used for registration.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        "/user-get",
        params={'username': 'unknown'},
        headers={"Authorization": "Basic " + admin_creds},
    )

    assert response.status_code == HTTPStatus.NOT_FOUND


def test_get_user_username_and_id_provided(user, admin_creds, client):
    """
    Test that providing both username and ID when retrieving a user results in a BAD_REQUEST error.
    
    Args:
        user: The registered test user.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        "/user-get",
        params={'username': user.username, 'id': user.uid},
        headers={"Authorization": "Basic " + admin_creds},
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_get_user_neither_username_nor_id_provided(user, admin_creds, client):
    """
    Test that providing neither username nor ID when retrieving a user results in a BAD_REQUEST error.
    
    Args:
        user: The registered test user.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        "/user-get",
        headers={"Authorization": "Basic " + admin_creds},
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_get_user_by_id(user, admin_creds, client):
    """
    Test that retrieving a user by ID returns the correct user details.
    
    Args:
        user: The registered test user.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        "/user-get",
        params={'id': user.uid},
        headers={"Authorization": "Basic " + admin_creds},
    )

    json = response.json()
    assert response.status_code == HTTPStatus.OK
    assert json['username'] == user.username
    assert json['uid'] == user.uid
    assert json['role'] == user.role


def test_user_get_with_invalid_password(user, client):
    """
    Test that using invalid credentials to retrieve a user results in an UNAUTHORIZED error.
    
    Args:
        user: The registered test user.
        client: The test client used to send API requests.
    """
    creds = base64.b64encode(f"admin:wrong-password".encode("ascii")).decode("utf-8")
    response = client.post(
        "/user-get",
        params={'id': user.uid},
        headers={"Authorization": "Basic " + creds},
    )

    assert response.status_code == HTTPStatus.UNAUTHORIZED


def test_user_promote(user, admin_creds, client):
    """
    Test that promoting a user with valid admin credentials succeeds.
    
    Args:
        user: The registered test user.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        '/user-promote',
        params={'id': user.uid},
        headers={"Authorization": "Basic " + admin_creds}
    )

    assert response.status_code == HTTPStatus.OK


def test_user_promote_not_being_admin(user, password, client):
    """
    Test that attempting to promote a user without admin rights results in a FORBIDDEN error.
    
    Args:
        user: The registered test user.
        password: The password used for registration.
        client: The test client used to send API requests.
    """
    creds = base64.b64encode(f"{user.username}:{password}".encode("ascii")).decode("utf-8")
    response = client.post(
        '/user-promote',
        params={'id': user.uid},
        headers={"Authorization": "Basic " + creds}
    )

    assert response.status_code == HTTPStatus.FORBIDDEN


def test_user_promote_unknown_user(user, password, admin_creds, client):
    """
    Test that attempting to promote a non-existing user results in a BAD_REQUEST error.
    
    Args:
        user: The registered test user.
        password: The password used for registration.
        admin_creds: Base64-encoded admin credentials.
        client: The test client used to send API requests.
    """
    response = client.post(
        '/user-promote',
        params={'id': 12345},
        headers={"Authorization": "Basic " + admin_creds}
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST
