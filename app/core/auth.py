from __future__ import annotations

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union
from pydantic import HttpUrl

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request, File, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson.objectid import ObjectId

from app.core import config
from app.database import helpers, db
from app.utils import get_random_string, get_unix_time
from .schema import Token, TokenData, AdminUpgrade, AdminDowngrade, \
    UpdateBase, SignupReturn, SignupUser, AdminBlock, AuthError, CurrentUser, RefToken

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

auth = APIRouter(prefix="/user", tags=["Authentication"])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def get_user_by_id(
        user_id: str
) -> dict[str, Any] | None:
    return helpers.get_user({"_id": ObjectId(user_id)})


def get_user(
        username: Optional[str],
) -> dict[str, Any] | None:
    return helpers.get_user({"username": username})


def authenticate_user(
        username: str,
        password: str,
) -> Union[bool, dict[str, Any]]:
    print("this is inside authenticate user", username, password)

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
        u = get_user(username)
        if not u:
            return JSONResponse(status_code=HTTPStatus.NOT_FOUND,
                                content={"detail": "username provided isn't assigned to any user"})


        elif u.get("superadmin"):
            return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                                content={"detail": "a superadmin can't alter status of superadmin"})

    return q


@auth.post("/signup", response_model=SignupReturn, responses={409: {"model": AuthError}})
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
        "avatar_url": dp_image,
        "refferal_code": get_random_string(15),
        "no_of_referrals": 0,
        "password": get_password_hash(user_data.password),
        "country": user_data.country,
        "facebook_id": user_data.facebook_id,
        "google_id": user_data.google_id,
        "disabled": False,
        "superadmin": False,
        "subadmin": False,
        "created": get_unix_time()
    }

    # print(d)
    user_obj = user.insert_one(d)

    print(user_obj)
    return {"status": 200, "message": "successfully created user", "error": ""}


@auth.post("/login", response_model=Token, responses={401: {"model": AuthError}})
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


@auth.put("/add-avatar", response_model=SignupReturn, responses={401: {"model": AuthError},
                                                                 500: {"model": AuthError}})
async def add_avatar(
        avatar: UploadFile, request: Request,
        auth: Depends = Depends(get_current_user)
):
    try:
        content = await avatar.read()

        f = open(f"static\image\/{avatar.filename}", "wb")
        f.write(content)
        f.close()

        helpers.update_user({"_id": ObjectId(auth["_id"])},
                            {"avatar": str(request.base_url) + f"image/{avatar.filename}"})
    except:
        return JSONResponse(status_code=HTTPStatus.INTERNAL_SERVER_ERROR, content={"detail": "some internal issues"})

    return {"status": 200, "message": "successfully updated avatar", "error": ""}


@auth.put("/update", response_model=SignupReturn,
          responses={401: {"model": AuthError}, 409: {"model": AuthError}})
async def update_user(
        user_data: UpdateBase = Body(...),
        auth: Depends = Depends(get_current_user)
) -> dict[str, Any]:
    changer = {}

    if user_data.firstname:
        changer["firstname"] = user_data.firstname
    if user_data.lastname:
        changer["lastname"] = user_data.lastname
    if user_data.avatar_url:
        changer["avatar_url"] = user_data.avatar_url
    if user_data.country:
        changer["country"] = user_data.country

    if not changer:
        return {"status": 200, "message": "no change due to empty body", "error": ""}

    up = helpers.update_user({"_id": ObjectId(auth["_id"])}, changer)

    if not up:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="sorry some error occured while updating the user")

    return {"status": 200, "message": f"successfully updated user {auth['username']}", "error": ""}


@auth.get("/current-user", response_model=CurrentUser)
async def get_current_user(auth: Depends = Depends(get_current_user)):
    auth["id"] = str(auth["_id"])
    auth.pop("_id")
    auth.pop("password")
    auth.pop("facebook_id")
    auth.pop("google_id")

    return auth


@auth.get("/referral-code", responses={200: {"model": RefToken}, 401: {"model": AuthError}})
async def get_token(request: Request, auth: Depends = Depends(get_current_user)):
    return {"token": auth.get('refferal_code')}


# ------------------------ ADMIN ------------------------------

@auth.post("/admin/upgrade", response_model=SignupReturn)
async def upgrade_to_admin(
        data: AdminUpgrade,
        auth: Depends = Depends(get_current_user)
) -> dict[str, Any]:
    """
    This route allows for the upgrade of user to a subadmin. It accepts a json object containing
    either an `id` or  `username`. upgrade is allowed base on privilege level i.e

    `
        superadmin > subadmin > general user
    `
    """
    id = data.id
    username = data.username
    if auth["superadmin"] and auth["subadmin"]:
        q = confirm_admin_body_legit(id, username)

        up = helpers.update_user(q, {"subadmin": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail=f"internal issue {up}")

        return {"status": 200, "message": f"successfully updated user {q.get('username') or q.get('_id')}", "error": ""}

    raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                        detail="you need super admin privileges to access this route")


@auth.post("/admin/downgrade", response_model=SignupReturn)
async def downgrade_from_admin(
        data: AdminDowngrade,
        auth: Depends = Depends(get_current_user)
) -> dict[str, Any]:
    """
    This route allows for the downgrade of user from a subadmin. It accepts a json object containing
    either an `id` or  `username`. downgrade is allowed base on privilege level i.e

    `
        superadmin > subadmin > general user
    `
    """

    id = data.id
    username = data.username
    if auth["superadmin"] and auth["subadmin"]:
        q = confirm_admin_body_legit(id, username)

        up = helpers.update_user(q, {"subadmin": False})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail=f"internal error")

        return {"status": 200,
                "message": f"successfully downgraded user {q.get('username') or q.get('_id')} from sub admin",
                "error": ""}

    raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                        detail="you need super admin privileges to access this route")


@auth.post("/admin/block", response_model=SignupReturn)
async def block_user(
        data: AdminDowngrade,
        auth: Depends = Depends(get_current_user)
) -> dict[str, Any]:
    """
    This route allows for the blockage of user. It accepts a json object containing
    either an `id` or  `username`. blocking is allowed base on privilege level i.e
    `
        superadmin > subadmin > general user
    `
    """
    id = data.id
    username = data.username

    by_id = get_user_by_id(id)
    by_username = get_user(username)

    q = {}
    user = {}
    if not by_id and not by_username:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=f"user with id {id} or username {username} not found")
    if by_id:
        q = {"_id": ObjectId(str(by_id["_id"]))}
        user = by_id
    else:
        q = {"username": str(username)}
        user = by_username

    if not user["subadmin"] and auth["subadmin"] and not auth["disabled"]:

        up = helpers.update_user(q, {"disabled": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully blocked user {user['username']}", "error": ""}

    elif user["subadmin"] and auth["superadmin"] and not auth["disabled"]:

        up = helpers.update_user(q, {"disabled": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully blocked user {user['username']}", "error": ""}

    else:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="you do not have the authority to block this user")
