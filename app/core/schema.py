from typing import Any, Optional, Union, List

from pydantic import BaseModel, HttpUrl, EmailStr

from fastapi import UploadFile


class IndexReturn(BaseModel):
    info: str


class User(BaseModel):
    username: EmailStr


class RefToken(BaseModel):
    token: str


class Platform(BaseModel):
    allow_invite: bool = True
    new_notifications: bool = True
    metioned: bool = True


class UserSetting(BaseModel):
    theme: str = ""
    platform: Platform
    teams: Platform


class partialUser(User):
    id: str
    firstname: str
    lastname: str
    location: Optional[str] = ""
    created: int | float  # this is in unix time
    disabled: bool
    group: str
    words_left: int = 0
    image_left: int = 0
    referral_code: str

class AdminUserList(BaseModel):
    users: List[partialUser] = []
    total: int = 0
    limit: int = 1
    page: int = 1

class CurrentUser(User):
    id: str
    firstname: str
    lastname: str
    bio: Optional[str] = ""
    location: Optional[str] = ""
    avatar_url: Optional[str] = "https://picsum.photos/536/354"
    created: int | float  # this is in unix time
    disabled: bool
    referral_code: str
    list_of_referral: Optional[list[str]]
    list_of_verified_referral: Optional[list[str]]
    country: str
    settings: UserSetting



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
    bio: Optional[str] = ""
    location: Optional[str] = ""


class UpdateBase(BaseModel):
    firstname: Optional[str]
    lastname: Optional[str]
    country: Optional[str]
    location: Optional[str]
    avatar_url: Optional[HttpUrl] = None
    bio: Optional[str]


class SignupUser(SignUpBase):
    password: str
    referrer_id: Optional[str] = None
    google_id: Optional[str] = None



class LoginUser(BaseModel):
    username: str
    password: str


class AdminUpgrade(BaseModel):
    id: Optional[str]
    username: Optional[str]


class AdminDowngrade(AdminUpgrade):
    pass


class AdminBlock(AdminUpgrade):
    pass


class Refer(BaseModel):
    refferer_id: Optional[str] = None


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    user: CurrentUser



class TokenData(BaseModel):
    username: Optional[str] = None


class AuthError(BaseModel):
    detail: str


class ForgetPasswordRequest(BaseModel):
    username: EmailStr

class UpdatePassword(BaseModel):
    new_password: str
    token: str

class CreateCheckoutSession(BaseModel):
    lookup_key: str




