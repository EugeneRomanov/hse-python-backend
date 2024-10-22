import base64
import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient
from lecture_4.demo_service.core.users import UserRole
from lecture_4.demo_service.api.utils import initialize
from lecture_4.demo_service.api.main import create_app

@pytest_asyncio.fixture
async def app() -> FastAPI:
    """Создает экземпляр FastAPI приложения для тестов."""
    app = create_app()
    async with initialize(app):
        yield app

@pytest_asyncio.fixture
async def client(app: FastAPI):
    """Создает асинхронного клиента для взаимодействия с FastAPI приложением."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

def basic_auth(username: str, password: str) -> dict:
    """Возвращает заголовок для Basic Authentication."""
    credentials = f"{username}:{password}".encode("utf-8")
    auth_header = base64.b64encode(credentials).decode("utf-8")
    return {"Authorization": f"Basic {auth_header}"}

@pytest.mark.asyncio
async def test_register_user(client: AsyncClient):
    """Тестирует успешную регистрацию нового пользователя."""
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
    """Тестирует регистрацию с некорректным паролем (слишком слабый пароль)."""
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
    """Тестирует регистрацию с паролем, не содержащим цифры."""
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
    """Тестирует попытку регистрации с уже существующим именем пользователя."""
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
    """Тестирует получение пользователя по имени пользователя с использованием Basic Auth."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"username": "admin"}
    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["username"] == "admin"
    assert json_response["name"] == "admin"

@pytest.mark.asyncio
async def test_get_user_by_id(client: AsyncClient):
    """Тестирует получение пользователя по ID."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": 1}
    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 200
    json_response = response.json()
    assert json_response["uid"] == 1
    assert json_response["username"] == "admin"

@pytest.mark.asyncio
async def test_get_user_without_id_or_username(client: AsyncClient):
    """Тестирует запрос без указания ID или имени пользователя."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "neither id nor username are provided"}

@pytest.mark.asyncio
async def test_get_user_not_found(client: AsyncClient):
    """Тестирует запрос пользователя, которого не существует."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    response = await client.post("/user-get", params={"id": 999}, headers=headers)
    assert response.status_code == 404

@pytest.mark.asyncio
async def test_promote_user(client: AsyncClient):
    """Тестирует успешное повышение пользователя до административной роли."""
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

@pytest.mark.asyncio
async def test_unauthorized_access(client: AsyncClient):
    """Тестирует доступ с некорректным токеном авторизации."""
    headers = {"Authorization": "Basic invalid_token"}
    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_value_error_handler(client: AsyncClient):
    """Тестирует ошибку при передаче одновременно ID и имени пользователя."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    params = {"id": 1, "username": "admin"}
    response = await client.post("/user-get", params=params, headers=headers)
    assert response.status_code == 400
    assert response.json() == {"detail": "both id and username are provided"}

@pytest.mark.asyncio
async def test_requires_author_unauthorized(client: AsyncClient):
    """Тестирует запрос с неверным пользователем и паролем."""
    headers = basic_auth("invalid_user", "wrong_password")
    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_value_error_handler_for_promote(client: AsyncClient):
    """Тестирует обработку ошибки при попытке повышения несуществующего пользователя."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    response = await client.post("/user-promote", params={"id": 999}, headers=headers)
    assert response.status_code == 400

@pytest.mark.asyncio
async def test_password_validation_failure(client: AsyncClient):
    """Тестирует ошибку валидации пароля при слишком коротком пароле."""
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
    """Тестирует попытку доступа с использованием несуществующего пользователя."""
    headers = basic_auth("nonexistent_user", "password")
    response = await client.post("/user-get", headers=headers)
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_requires_admin_forbidden(client: AsyncClient):
    """Тестирует ошибку доступа при попытке повышения обычного пользователя до администратора."""
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
    """Тестирует попытку повышения до администратора для несуществующего пользователя."""
    headers = basic_auth("admin", "superSecretAdminPassword123")
    response = await client.post("/user-promote", params={"id": 999}, headers=headers)
    assert response
