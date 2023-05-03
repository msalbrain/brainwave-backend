from typing import Any, Optional, Union

from pydantic import BaseModel, HttpUrl, EmailStr

from fastapi import UploadFile


class User(BaseModel):
    username: EmailStr


class UserInDB(User):
    disabled: Optional[bool] = None
    password: str
    admin: str
    created: int | float


class SignupReturn(BaseModel):
    status: int
    message: Any
    error: str


class SignUpBase(User):
    firstname: str
    lastname: str
    country: str
    avatar_url: Optional[HttpUrl] = None


class SignupUser(SignUpBase):
    password: str

    facebook_id: Optional[str] = None
    google_id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None
