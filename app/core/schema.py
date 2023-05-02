from typing import Any, Optional, Union

from pydantic import BaseModel


class User(BaseModel):
    username: str
    disabled: Optional[bool] = None


class UserInDB(User):
    hashed_password: str
    admin: str
    created: int | float


class SignupReturn(BaseModel):
    status: int
    message: str
    error: str


class SignupUser(User):
    first_name: str
    last_name: str
    password: str
    country: str
    facebook_id: Optional[str] = None
    google_id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
