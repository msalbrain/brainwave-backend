from __future__ import annotations
from uuid import uuid4

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request, File, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson.objectid import ObjectId

from app.core import config
from app.database import helpers, db
from app.utils import get_unix_time
from .schema import TokenData, SignupUser
from app.database.helpers import get_user_in_db, update_user

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_id(
        user_id: str
) -> dict[str, Any] | None:
    return helpers.get_user_in_db({"_id": ObjectId(user_id)})


def get_user(
        username: Optional[str],
) -> dict[str, Any] | None:
    return helpers.get_user_in_db({"username": username})


def authenticate_user(
        username: str,
        password: str,
) -> Union[bool, dict[str, Any]]:
    user = get_user_in_db({"username": username})

    if not user:
        return False
    if not verify_password(password, user["password"]):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> bytes | str:
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        config.API_SECRET_KEY,
        algorithm=config.API_ALGORITHM,
    )
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    credentials_exception = HTTPException(
        status_code=HTTPStatus.UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(
            token,
            config.API_SECRET_KEY,
            algorithms=[config.API_ALGORITHM],
        )
        username = payload.get("sub")

        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)

    except JWTError:
        raise credentials_exception

    user = get_user_in_db(username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


def confirm_admin_body_legit(user_id, username):
    q = {}
    if user_id:
        q = {"_id": ObjectId(user_id)}
        u = get_user_by_id(user_id)
        if not u:
            return JSONResponse(status_code=HTTPStatus.NOT_FOUND,
                                content={"detail": "id provided isn't assigned to any user"})

        if not u.get("username"):
            return JSONResponse(status_code=HTTPStatus.NOT_FOUND,
                                content={"detail": "username provided isn't assigned to any user"})

        if u.get("superadmin"):
            return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                                content={"detail": "a superadmin can't alter status of superadmin"})

    elif username:
        q = {"username": username}
        u = get_user_in_db(username)
        if not u:
            return JSONResponse(status_code=HTTPStatus.NOT_FOUND,
                                content={"detail": "username provided isn't assigned to any user"})

        elif u.get("superadmin"):
            return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                                content={"detail": "a superadmin can't alter status of superadmin"})

    return q


def validate_ref(user_data: SignupUser):
    """
    This function helps with the validation of referral token
    And update referral user object
    """
    new_user_id = str(uuid4()).replace('-', '')  # generate id for new user
    _id = str(uuid4()).replace('-', '')  # generate id for refferal

    u = get_user_in_db({"referral_code": user_data.referrer_id})
    if not u:
        return {"verify": False, "data": {"assign_id": new_user_id, }}
    elif u["username"] == user_data.username:
        raise HTTPException(status_code=409,
                            detail=f"referral code provide belongs to username `{user_data.username}` provided.")

    ref_obj = {
        "_id": _id,
        "active": False,
        "referral_user_id": str(u["_id"]),
        "referred_user_id": new_user_id,
        "referral_code": user_data.referrer_id
    }

    u["list_of_referral"].append(new_user_id)  # added new user_id to referral user object
    u["list_of_referral"] = list(set(u["list_of_referral"]))  # reduce redundancy

    update_user({"username": u["username"]}, {"list_of_referral": u["list_of_referral"]}) # update referral user
    # object in db

    return {"verify": False, "data": {"assign_id": new_user_id}}


def generate_password_change_object(user_id):
    t = get_unix_time()
    d = {
        "created": t,
        "expire": t + 600,
        "token": str(uuid4()).replace("-", ""),
        "user_id": user_id
    }

    return d

