from __future__ import annotations
from uuid import uuid4

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union, Annotated
from pprint import pprint
import pickle

from fastapi import Depends, HTTPException, Header
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from jose import jwt
from passlib.context import CryptContext

from app.core import config
from app.database import helpers
from app.utils import get_unix_time
from .schema.auth import SignupUser
from app.database.helpers import get_user_in_db, update_user
from app.database import helpers as db_helper
from app.database.db import referral_col
from app.core.dependency import AuthJWT

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_id(
        user_id: str
) -> dict[str, Any] | None:
    return helpers.get_user_in_db({"_id": user_id})


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


async def get_current_user(Authorization: Annotated[str | None, Header(convert_underscores=False,
                                                                       description="This is of type Bearer i.e `Authorization: Bearer <token>`")] = None,
                           Authorize: AuthJWT = Depends()) -> dict[str, Any]:
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail=f"user not found user -- {Authorize.get_jwt_subject()}")

    return auth


def confirm_admin_body_legit(user_id, username):
    q = {}
    if user_id:
        q = {"_id": user_id}
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
        u = get_user_in_db(q)
        if not u:
            return JSONResponse(status_code=HTTPStatus.NOT_FOUND,
                                content={"detail": "username provided isn't assigned to any user"})

        elif u.get("superadmin"):
            return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                                content={"detail": "a superadmin can't alter status of superadmin"})

    return q


def validate_ref(user_data: SignupUser, new_user_id: str):
    """
    This function helps with the validation of referral token
    And update referral user object

    """

    _id = str(uuid4()).replace('-', '')  # generate id for refferal

    u = get_user_in_db({"referral_code": user_data.referrer_id})
    if not u:
        return {"verify": False, "data": {"assign_id": new_user_id, }}

    elif u["username"] == user_data.username:
        raise HTTPException(status_code=409,
                            detail=f"referral code provide belongs to username `{user_data.username}` provided.")

    ref_obj = {
        "_id": _id,
        "referral_user_id": str(u["_id"]),
        "referred_user_id": new_user_id,
        "referral_code": user_data.referrer_id,
        "created": get_unix_time()
    }

    referral_col.insert_one(ref_obj)  # added new referral obj

    u["list_of_referral"].append(new_user_id)  # added new user_id to referral user object
    u["list_of_referral"] = list(set(u["list_of_referral"]))  # reduce redundancy

    update_user({"username": u["username"]}, {"list_of_referral": u["list_of_referral"]})  # update referral user
    # object in db

    return {"verify": False, "data": {"assign_id": new_user_id}}


def validate_google_ref(google_user_data, referrer_id):
    """
    This function helps with the validation of referral token
    And update referral user object

    """

    _id = str(uuid4()).replace('-', '')  # generate id for refferal

    u = get_user_in_db({"referral_code": referrer_id})
    if not u:
        return {"verify": False, "data": {"assign_id": google_user_data["sub"], }}

    elif u["username"] == google_user_data["email"]:
        raise HTTPException(status_code=409,
                            detail=f"referral code provide belongs to username `{google_user_data['email']}` provided.")

    ref_obj = {
        "_id": _id,
        "referral_user_id": str(u["_id"]),
        "referred_user_id": google_user_data["sub"],
        "referral_code": referrer_id,
        "created": get_unix_time()
    }

    referral_col.insert_one(ref_obj)  # added new referral obj

    u["list_of_referral"].append(google_user_data["sub"])  # added new user_id to referral user object
    u["list_of_referral"] = list(set(u["list_of_referral"]))  # reduce redundancy

    update_user({"username": u["username"]}, {"list_of_referral": u["list_of_referral"]})  # update referral user
    # object in db

    return {"verify": False}


def verify_user(referred_user_id: str):
    reefed_user = referral_col.find_one({"referred_user_id": referred_user_id})
    pprint(reefed_user)
    if not reefed_user:
        pass
        # TODO: Come back and add logging for `user with referred_user_id not found`

    referral_user_obj = get_user_in_db({"_id": reefed_user["referral_user_id"]})

    if not referral_user_obj:
        raise Exception("Problem wa")

    referral_user_obj["list_of_verified_referral"].append(referred_user_id)  # added new user_id to referral user object
    referral_user_obj["list_of_verified_referral"] = list(
        set(referral_user_obj["list_of_verified_referral"]))  # remove redundancy

    return update_user({"_id": reefed_user["referral_user_id"]},
                       {"list_of_verified_referral": referral_user_obj[
                          "list_of_verified_referral"]})  # update referral user object in db


def generate_password_change_object(user_id):
    t = get_unix_time()
    tok = str(uuid4()).replace("-", "")

    d = {
        "created": t,
        "expire": t + 600,
        "token": tok,
        "user_id": user_id
    }

    db_helper.add_to_cache(d, exp=10, key=tok)

    return d

