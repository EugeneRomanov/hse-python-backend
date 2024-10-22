import base64
from typing import AsyncGenerator, Dict

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient

from lecture_4.demo_service.core.users import UserRole
from lecture_4.demo_service.api.utils import initialize
from lecture_4.demo_service.api.main import create_app

# Constants
TEST_BASE_URL = "http://test"
ADMIN_CREDENTIALS = ("admin", "superSecretAdminPassword123")
VALID_USER_DATA = {
    "username": "newuser",
    "name": "New User",
    "birthdate": "1990-01-01T00:00:00Z",
    "password": "password123",
}

# Fixtures
@pytest_asyncio.fixture
async def app() -> AsyncGenerator[FastAPI, None]:
    app = create_app()
    async with initialize(app):
        yield app

@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(app=app, base_url=TEST_BASE_URL) as client:
        yield client

# Helper functions
def create_basic_auth_header(username: str, password: str) -> Dict[str, str]:
    """Create Basic Auth header with given credentials."""
    credentials = f"{username}:{password}".encode("utf-8")
    auth_header = base64.b64encode(credentials).decode("utf-8")
    return {"Authorization": f"Basic {auth_header}"}

async def register_test_user(client: AsyncClient, user_data: dict) -> dict:
    """Helper function to register a test user."""
    response = await client.post("/user-register", json=user_data)
    return response.json() if response.status_code == 200 else None

# Tests
@pytest.mark.asyncio
class TestUserRegistration:
    async def test_successful_registration(self, client: AsyncClient):
        response = await client.post("/user-register", json=VALID_USER_DATA)
        assert response.status_code == 200
        
        user_data = response.json()
        assert user_data["username"] == VALID_USER_DATA["username"]
        assert user_data["name"] == VALID_USER_DATA["name"]
        assert user_data["role"] == UserRole.USER.value

    async def test_invalid_password_formats(self, client: AsyncClient):
        test_cases = [
            {"password": "weakpass", "desc": "too_short"},
            {"password": "longpasswordwithoutdigit", "desc": "no_digit"},
        ]
        
        for case in test_cases:
            invalid_data = VALID_USER_DATA.copy()
            invalid_data["password"] = case["password"]
            response = await client.post("/user-register", json=invalid_data)
            assert response.status_code == 400

    async def test_duplicate_username(self, client: AsyncClient):
        # First registration should succeed
        await register_test_user(client, VALID_USER_DATA)
        
        # Second registration with same username should fail
        response = await client.post("/user-register", json=VALID_USER_DATA)
        assert response.status_code == 400
        assert response.json() == {"detail": "username is already taken"}

@pytest.mark.asyncio
class TestUserRetrieval:
    async def test_get_user_by_username(self, client: AsyncClient):
        headers = create_basic_auth_header(*ADMIN_CREDENTIALS)
        response = await client.post(
            "/user-get",
            params={"username": "admin"},
            headers=headers
        )
        assert response.status_code == 200
        user_data = response.json()
        assert user_data["username"] == "admin"
        assert user_data["name"] == "admin"

    async def test_get_user_by_id(self, client: AsyncClient):
        headers = create_basic_auth_header(*ADMIN_CREDENTIALS)
        response = await client.post(
            "/user-get",
            params={"id": 1},
            headers=headers
        )
        assert response.status_code == 200
        user_data = response.json()
        assert user_data["uid"] == 1
        assert user_data["username"] == "admin"

    async def test_invalid_user_queries(self, client: AsyncClient):
        headers = create_basic_auth_header(*ADMIN_CREDENTIALS)
        
        # Test missing parameters
        response = await client.post("/user-get", headers=headers)
        assert response.status_code == 400
        assert response.json() == {"detail": "neither id nor username are provided"}

        # Test non-existent user
        response = await client.post("/user-get", params={"id": 999}, headers=headers)
        assert response.status_code == 404

@pytest.mark.asyncio
class TestUserPromotion:
    async def test_successful_promotion(self, client: AsyncClient):
        # Register a new user first
        user_data = await register_test_user(client, VALID_USER_DATA)
        
        # Promote the user
        headers = create_basic_auth_header(*ADMIN_CREDENTIALS)
        response = await client.post(
            "/user-promote",
            params={"id": user_data["uid"]},
            headers=headers
        )
        assert response.status_code == 200
        assert response.text == ""

    async def test_promotion_restrictions(self, client: AsyncClient):
        # Register a regular user
        regular_user_data = {
            "username": "regular_user",
            "name": "Regular User",
            "birthdate": "1990-01-01T00:00:00Z",
            "password": "password12345",
        }
        await register_test_user(client, regular_user_data)
        
        # Try to promote with regular user credentials
        headers = create_basic_auth_header("regular_user", "password12345")
        response = await client.post(
            "/user-promote",
            params={"id": 1},
            headers=headers
        )
        assert response.status_code == 403

@pytest.mark.asyncio
class TestAuthentication:
    async def test_invalid_authentication(self, client: AsyncClient):
        test_cases = [
            {"headers": {"Authorization": "Basic invalid_token"}, "expected_status": 401},
            {"headers": create_basic_auth_header("invalid_user", "wrong_password"), "expected_status": 401},
            {"headers": create_basic_auth_header("nonexistent_user", "password"), "expected_status": 401},
        ]
        
        for case in test_cases:
            response = await client.post("/user-get", headers=case["headers"])
            assert response.status_code == case["expected_status"]