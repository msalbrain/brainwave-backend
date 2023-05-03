from __future__ import annotations

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union
from pydantic import HttpUrl

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request, File, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core import config
from app.database import helpers, db
from app.utils import get_random_string, get_unix_time
from .schema import Token, TokenData, SignUpBase, UserInDB, SignupReturn, SignupUser

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")
auth = APIRouter(prefix="/user", tags=["User"])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user(
        username: Optional[str],
) -> dict[str, Any] | None:
    return helpers.get_user({"username": username})


def authenticate_user(
        username: str,
        password: str,
) -> Union[bool, dict[str, Any]]:
    user = get_user(username)
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

    user = get_user(username=token_data.username)

    if user is None:
        raise credentials_exception

    return user


@auth.post("/signup", response_model=SignupReturn)
async def create_new_user(
        request: Request, user_data: SignupUser = Body(...)
) -> dict[str, Any]:
    u = get_user(user_data.username)
    if u:
        raise HTTPException(
            status_code=409,
            detail="user already exist",
        )

    user = db.db["user"]
    dp_image = ""

    if user_data.avatar_url:
        dp_image = user_data.avatar_url
    # elif avatar:
    #     dp_image = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRskHid7mZQ0cFayfddXhv10ZSCadb06LRuTg&usqp=CAU"

    d = {
        "firstname": user_data.firstname,
        "lastname": user_data.lastname,
        "username": user_data.username,
        "avatar": dp_image,
        "refferal_code": get_random_string(15),
        "password": get_password_hash(user_data.password),
        "country": user_data.country,
        "facebook_id": user_data.facebook_id,
        "google_id": user_data.google_id,
        "disabled": False,
        "superadmin": False,
        "generaladmin": False,
        "created": get_unix_time()
    }
    #
    # print(d)
    # user_obj = user.insert_one(d)

    return {"status": 200, "message": "successfully added user", "error": ""}


@auth.post("/login", response_model=Token)
async def login_for_access_token(
        form_data: OAuth2PasswordRequestForm = Depends(),
) -> dict[str, Any]:
    user = authenticate_user(
        form_data.username,
        form_data.password,
    )

    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(
        seconds=config.API_ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    access_token = create_access_token(
        data={"sub": user["username"]},  # type: ignore
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@auth.put("/add-avatar", response_model=SignupReturn)
async def add_avatar(
        avatar: UploadFile, request: Request,
        auth: Depends = Depends(get_current_user)
):
    content = await avatar.read()

    f = open(f"static\image\/{avatar.filename}", "wb")
    f.write(content)
    f.close()



    helpers.update_user({"_id": auth["_id"]}, {"avatar": str(request.base_url) + f"image/{avatar.filename}"})

    return {"status": 200, "message": "successfully updated avatar", "error": ""}


@auth.put("/update", response_model=SignupReturn)
async def update_user(
        user_data: SignUpBase = Body(...),
        auth: Depends = Depends(get_current_user)
):
    try:
        changer = {}

        if user_data.firstname:
            changer["firstname"] = user_data.firstname
        if user_data.lastname:
            changer["lastname"] = user_data.lastname
        if user_data.avatar_url:
            changer["avatar_url"] = user_data.avatar_url
        if user_data.country:
            changer["country"] = user_data.country

        helpers.update_user({"_id": auth["_id"]}, changer)

        return {"status": 200, "message": f"successfully updated user {auth['username']}", "error": ""}

    except:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="sorry seems like we are facing some internal error")



@auth.get("/current-user")
async def get_current_user(auth: Depends = Depends(get_current_user)):
    auth["id"] = str(auth["_id"])
    auth.pop("_id")
    auth.pop("password")

    return auth
