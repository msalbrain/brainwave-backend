from typing import Any, Optional, Union

from pydantic import BaseModel, HttpUrl, EmailStr

from fastapi import UploadFile


class IndexReturn(BaseModel):
    info: str


class User(BaseModel):
    username: EmailStr


class UserInDB(User):
    disabled: Optional[bool] = None
    password: str
    admin: str
    created: int | float

class RefToken(BaseModel):
    token: str


class CurrentUser(User):
    id: str
    firstname: str
    lastname: str
    avatar_url: Optional[HttpUrl]
    created: int | float # this is dada do
    refferal_code: str
    no_of_referrals: int
    country: str

    class Config:
        schema_extra = {
            "example": {
                "id": "507f1f77bcf86cd799439011",
                "firstname": "idan",
                "lastname": "idan",
                "avatar_url": "https://picsum.photos/536/354",
                "created": 1683172624,
                "refferal_code": "fghjkmzbvexdtyui",
                "no_of_referrals": 2,
                "country": "sardine"
            }
        }


class SignupReturn(BaseModel):
    status: int
    message: Any
    error: str


class SignUpBase(User):
    firstname: str
    lastname: str
    country: str
    avatar_url: Optional[HttpUrl] = None


class UpdateBase(BaseModel):
    firstname: Optional[str]
    lastname: Optional[str]
    country: Optional[str]
    avatar_url: Optional[HttpUrl] = None


class AdminUpgrade(BaseModel):
    id: Optional[str]
    username: Optional[str]


class AdminDowngrade(AdminUpgrade):
    pass


class AdminBlock(AdminUpgrade):
    pass


class SignupUser(SignUpBase):
    password: str

    google_id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class AuthError(BaseModel):
    detail: str
