import os
from typing import Annotated

from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlmodel import Session, create_engine

from models import User
from security import verify_access_token

# Load environment variables from .env file
load_dotenv()

print("Loaded environment variables:")
print(f".env debugging: {os.getenv('DB_USER')}")

DB_USER = os.getenv("DB_USER", "sahal")
DB_PASSWORD = os.getenv("DB_PASSWORD", "sahalprojects9078")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME", "devpulse_db")

# Use DATABASE_URL directly if it exists (e.g., from Neon.tech or Render)
DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
)
engine = create_engine(DATABASE_URL, echo=True)


def get_session():
    with Session(engine) as session:
        yield session


# 1. Instructs Swagger UI and FastAPI where to look for authentication headers
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: Session = Depends(get_session),
) -> User:
    """FastAPI dependency to secure routes. Validates JWT and injects the current active User object."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Please log in again.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Decode the token payload
    payload = verify_access_token(token)
    if payload is None:
        raise credentials_exception

    user_id: str = payload.get("sub")
    if user_id is None:
        raise credentials_exception

    # Fetch the actual user from the database container
    user = session.get(User, int(user_id))
    if user is None:
        raise credentials_exception

    return user
