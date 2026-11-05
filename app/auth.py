import secrets
from pathlib import Path

from dotenv import dotenv_values
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials


security = HTTPBasic()

env_path = Path(__file__).resolve().parent.parent / ".env"
config = dotenv_values(env_path)

expected_username = config.get("SOC_DASHBOARD_USERNAME")
expected_password = config.get("SOC_DASHBOARD_PASSWORD")

if not expected_username or not expected_password:
    raise RuntimeError("SOC credentials are missing from .env")


def require_soc_login(
    credentials: HTTPBasicCredentials = Depends(security)
):
    username_valid = secrets.compare_digest(
        credentials.username.encode("utf-8"),
        expected_username.encode("utf-8")
    )

    password_valid = secrets.compare_digest(
        credentials.password.encode("utf-8"),
        expected_password.encode("utf-8")
    )

    if not (username_valid and password_valid):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SOC credentials",
            headers={"WWW-Authenticate": "Basic"}
        )

    return credentials.username
