from typing import Any, Optional, Union, List
from pydantic import BaseModel, HttpUrl, EmailStr
from fastapi import UploadFile

from app.core import config


class CreateCheckoutSession(BaseModel):
    lookup_key: str


class CreateCheckoutSessionOut(BaseModel):
    status: int
    redirect_url: HttpUrl


class CustomerPortal(BaseModel):
    return_url: Optional[HttpUrl] = config.APP_URL


class CustomerPortalOut(CreateCheckoutSessionOut):
    pass
