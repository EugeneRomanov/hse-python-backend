import base64
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from lecture_4.demo_service.core.users import UserRole
from lecture_4.demo_service.api.utils import initialize
from lecture_4.demo_service.api.main import create_app


@pytest_asyncio.fixture
async def get_app() -> FastAPI:
    app = create_app()
    async with initialize(app):
        yield app


@pytest_asyncio.fixture
async def client(get_app: FastAPI):
    async with AsyncClient(app=get_app, base_url="http://test") as client:
        yield client


def basic_auth(username: str, password: str) -> dict[str, str]:
    credentials = f"{username}:{password}".encode("utf-8")
    auth_header = base64.b64encode(credentials).decode("utf-8")
    return {"Authorization": f"Basic {auth_header}"}


@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    request_body = {
        "username": "newuser",
        "name": "New User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "password123",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    json_response = response.json()
    assert json_response["username"] == "newuser"
    assert json_response["name"] == "New User"
    assert json_response["role"] == UserRole.USER.value


@pytest.mark.asyncio
@pytest.mark.parametrize("username,password,status_code", [
    ("weakuser", "weakpass", 400),
    ("user_without_digit", "longpasswordwithoutdigit", 400),
    ("shortpassworduser", "short", 400)
])
async def test_register_user_invalid_password(client: AsyncClient, username, password, status_code):
    request_body = {
        "username": username,
        "name": "Test User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": password,
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == status_code, f"Expected {status_code}, got {response.status_code}"


@pytest.mark.asyncio
async def test_register_user_name_taken(client: AsyncClient):
    request_body = {
        "username": "newuser",
        "name": "New User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "password123",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 200

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 400
    assert response.json() == {"detail": "username is already taken"}


@pytest.mark.asyncio
async def test_get_user_by_username(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"username": "admin"}

    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    json_response = response.json()
    assert json_response["username"] == "admin"
    assert json_response["name"] == "admin"


@pytest.mark.asyncio
async def test_get_user_by_id(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": 1}

    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    json_response = response.json()
    assert json_response["uid"] == 1
    assert json_response["username"] == "admin"
