from typing import Any, Optional, Union, List
from pydantic import BaseModel, HttpUrl, EmailStr
from fastapi import UploadFile

from app.core import config
from .auth import *


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

class AdminCreateNewUser(SignupUser):
    pass

class AdminUpdate(AdminUserDetail):
    firstname: Optional[str]
    lastname: Optional[str]
    country: Optional[str]
    bio: Optional[str]
    location: Optional[str]


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
