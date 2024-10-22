import base64
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from lecture_4.demo_service.core.users import UserRole
from lecture_4.demo_service.api.utils import initialize
from lecture_4.demo_service.api.main import create_app

# Фикстуры для приложения и клиента
@pytest_asyncio.fixture
async def app() -> FastAPI:
    app = create_app()
    async with initialize(app):  # ensure the app is properly initialized
        yield app


@pytest_asyncio.fixture
async def client(app: FastAPI):
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client


# Вспомогательная функция для базовой авторизации
def basic_auth(username: str, password: str) -> dict:
    credentials = f"{username}:{password}".encode("utf-8")
    auth_header = base64.b64encode(credentials).decode("utf-8")
    return {"Authorization": f"Basic {auth_header}"}


# Тесты для регистрации пользователя
@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    request_body = {
        "username": "newuser",
        "name": "New User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "password123",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 200
    json_response = response.json()

    assert json_response["username"] == "newuser"
    assert json_response["name"] == "New User"
    assert json_response["role"] == UserRole.USER.value


@pytest.mark.asyncio
async def test_register_user_invalid_password(client: AsyncClient):
    request_body = {
        "username": "weakuser",
        "name": "Weak User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "weakpass",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_register_user_password_without_digit(client: AsyncClient):
    request_body = {
        "username": "user_without_digit",
        "name": "User Without Digit",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "longpasswordwithoutdigit",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 400
    assert response.json() == {"detail": "invalid password"}


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

    # Повторная попытка регистрации с тем же именем пользователя
    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 400
    assert response.json() == {"detail": "username is already taken"}


# Тесты для получения пользователя
@pytest.mark.asyncio
async def test_get_user_by_username(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"username": "admin"}

    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200
    json_response = response.json()

    assert json_response["username"] == "admin"
    assert json_response["name"] == "admin"


@pytest.mark.asyncio
async def test_get_user_by_id(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": 1}

    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200
    json_response = response.json()

    assert json_response["uid"] == 1
    assert json_response["username"] == "admin"


@pytest.mark.asyncio
async def test_get_user_without_id_or_username(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")

    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "neither id nor username are provided"}


@pytest.mark.asyncio
async def test_get_user_not_found(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")

    response = await client.post("/user-get", params={"id": 999}, headers=headers)
    assert response.status_code == 404


# Тесты для повышения прав пользователя
@pytest.mark.asyncio
async def test_promote_user(client: AsyncClient):
    request_body = {
        "username": "newuser",
        "name": "New User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "password123",
    }

    response_json = (await client.post("/user-register", json=request_body)).json()

    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": response_json["uid"]}

    response = await client.post("/user-promote", params=params, headers=headers)
    assert response.status_code == 200
    assert response.text == ""


# Тесты на авторизацию и ошибки
@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    headers = {"Authorization": "Basic invalid_token"}

    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_value_error_handler(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": 1, "username": "admin"}

    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "both id and username are provided"}


@pytest.mark.asyncio
async def test_requires_author_unauthorized(client: AsyncClient):
    headers = basic_auth("invalid_user", "wrong_password")

    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_value_error_handler_for_promote(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")

    response = await client.post("/user-promote", params={"id": 999}, headers=headers)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_password_validation_failure(client: AsyncClient):
    request_body = {
        "username": "shortpassworduser",
        "name": "Short Password",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "short",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_requires_author_missing_user(client: AsyncClient):
    headers = basic_auth("nonexistent_user", "password")

    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_requires_admin_forbidden(client: AsyncClient):
    request_body = {
        "username": "regular_user",
        "name": "Regular User",
        "birthdate": "1990-01-01T00:00:00Z",
        "password": "password12345",
    }

    response = await client.post("/user-register", json=request_body)
    assert response.status_code == 200

    headers = basic_auth("regular_user", "password12345")
    response = await client.post("/user-promote", params={"id": 1}, headers=headers)

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_grant_admin_user_not_found(client: AsyncClient):
    headers = basic_auth("admin", "superSecretAdminPassword123")

    response = await client.post("/user-promote", params={"id": 999}, headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "user not found"}
