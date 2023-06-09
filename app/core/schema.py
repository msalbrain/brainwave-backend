from typing import Any, Optional, Union, List
from pydantic import BaseModel, HttpUrl, EmailStr
from fastapi import UploadFile

from app.core import config


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


class LoginUser(BaseModel):
    username: str
    password: str


class GoogleToken(BaseModel):
    token: str
    referrer_id: Optional[str] = None


class AdminUpgrade(BaseModel):
    id: Optional[str]
    username: Optional[str]


class AdminDowngrade(AdminUpgrade):
    pass


class AdminBlock(AdminUpgrade):
    block: bool
    pass


class AdminUserDetail(AdminUpgrade):
    pass


class AdminUpdate(BaseModel):
    firstname: Optional[str]
    lastname: Optional[str]
    country: Optional[str]
    bio: Optional[str]
    location: Optional[str]


"""

d = {
        "_id": new_user_id,
        "firstname": user_data.firstname,
        "lastname": user_data.lastname,
        "username": user_data.username,
        "bio": user_data.bio,
        "location": user_data.location,
        "avatar_url": dp_image,
        "customer_id": "",
        "referral_code": str(uuid4()).replace('-', ''),
        "list_of_referral": [],
        "list_of_verified_referral": [],
        "password": get_password_hash(user_data.password),
        "password_changed": {  # TODO: work the change password logic and update its object
            "last_date": t,
            "token": ""
        },
        "country": user_data.country,
        "google_id": "",
        "disabled": False,
        "verified": False,
        "super_admin": False,
        "sub_admin": False,
        "subscribed": False,
        "updated": t,
        "created": t,
        "settings": {
            "theme": "light",
            "platform": {
                "allow_invite": True,
                "new_notifications": True,
                "mentioned": True
            },
            "teams": {
                "allow_invite": True,
                "new_notifications": True,
                "mentioned": True
            }
        }
    }
"""


class AdminUserDetailReturn(BaseModel):
    id: str
    firstname: str
    lastname: str
    username: str
    bio: str
    location: str
    avatar_url: Optional[HttpUrl]
    customer_id: str
    referral_code: str
    country: str
    disabled: bool
    verified: bool
    super_admin: bool
    sub_admin: bool
    subscribed: bool
    updated: int
    created: int


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


class CreateCheckoutSessionOut(BaseModel):
    status: int
    redirect_url: HttpUrl


class CustomerPortal(BaseModel):
    return_url: Optional[HttpUrl] = config.APP_URL


class CustomerPortalOut(CreateCheckoutSessionOut):
    pass
