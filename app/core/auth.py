from __future__ import annotations

import asyncio
from uuid import uuid4

from datetime import datetime, timedelta
from http import HTTPStatus
from typing import Any, Optional, Union
from pydantic import HttpUrl, EmailStr, ValidationError

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request, File, \
    Body, BackgroundTasks, Query, Header
from fastapi.logger import logger
from fastapi.responses import JSONResponse
from fastapi_jwt_auth import AuthJWT
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from fastapi_jwt_auth.exceptions import AuthJWTException

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.core import config
from app.database import helpers as db_helper, db, cache

from app.utils import get_random_string, get_unix_time
from .schema import Token, TokenData, AdminUpgrade, AdminDowngrade, \
    UpdateBase, SignupReturn, SignupUser, AdminBlock, AuthError, \
    CurrentUser, RefToken, AdminUserList, LoginUser, \
    UpdatePassword, ForgetPasswordRequest

from app.core.utils import get_password_hash, get_user_by_id, get_current_user, \
    get_user_in_db, authenticate_user, confirm_admin_body_legit, validate_ref, generate_password_change_object

from app.mail import conf

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")


class AuthSettings(BaseModel):
    authjwt_secret_key: str = config.API_SECRET_KEY
    # Configure application to store and get JWT from cookies
    # authjwt_token_location: set = {"cookies"}
    # Disable CSRF Protection for this example. default is True
    # authjwt_cookie_csrf_protect: bool = False


@AuthJWT.load_config
def get_config():
    return AuthSettings()


auth = APIRouter(prefix="/user", tags=["Authentication"])


@auth.post("/signup", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def create_new_user(
        background_tasks: BackgroundTasks,
        request: Request, user_data: SignupUser = Body(...)
) -> dict[str, Any]:
    """
       Create a new user. This is one of the ways of initializing a new user into
       the system.
       **Note**: Any parameter not being used shouldn't be added.

        - **username**: `required` each user must be an email.
        - **password**: `required` each user must have a password.
        - **firstname**: `required` each user must have a firstname.
        - **lastname**: `required` each user must have a lastname.
        - **country**: `required` each user must have a country.
        - **avatar_url**: `optional` an image url e.g `http://image.jpg` is what should be provided. if an image object is what
        is in hand there is a route named `v1/user/add-avatar` for that (NOTE: you must signup first).
        - **bio**: `required` each item must have a bio.
        - **location**: `required` each user must have a location preferably `city, state`.
        - **referrer_id**: `optional` this field is the id of the referral. It is optional.
       \f
       :param user_data: User input.
       """

    u = get_user_in_db({"username": user_data.username})

    if u:
        raise HTTPException(
            status_code=409,
            detail="user already exist",
        )

    ref = validate_ref(user_data)

    user = db.db["user"]
    dp_image = ""

    if user_data.avatar_url:
        dp_image = user_data.avatar_url
    else:
        dp_image = config.USER_DEFAULT_IMAGE

    t = get_unix_time()

    d = {
        "_id": ref["data"]["assign_id"],
        "firstname": user_data.firstname,
        "lastname": user_data.lastname,
        "username": user_data.username,
        "bio": user_data.bio,
        "location": user_data.location,
        "avatar_url": dp_image,
        "referral_code": str(uuid4()).replace('-', ''),
        "list_of_referral": [],
        "list_of_verified_referral": [],
        "password": get_password_hash(user_data.password),
        "password_changed": {  # TODO: work the change password logic and update its object
            "date": t,
            "token": ""
        },
        "country": user_data.country,
        "google_id": "",
        "disabled": False,
        "super_admin": False,
        "sub_admin": False,
        "subcribed": False,
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

    user_obj = user.insert_one(d)

    message = MessageSchema(
        subject="Welcome to Brainwave - Confirm Your Email Address",
        recipients=[d["username"]],
        template_body={
            "app_name": "brainwave",
            "title": "New user",
            "firstname": d["firstname"],
            "support_email": "brainwave@mail.com",
            "link": "https://brainwave-five.vercel.app"
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="new_user.html")


    return {"status": 200, "message": "successfully created user", "error": ""}


@auth.post("/login", response_model=Token, responses={401: {"model": AuthError}})
async def login_for_access_token(
        user_cred: LoginUser, Authorize: AuthJWT = Depends()
) -> dict[str, Any]:
    """
        Login a user. This route returns an access token and a refresh token.

        - **username**: `required` each user must be an email.
        - **password**: `required` each user must have a password.

       """

    user = authenticate_user(
        user_cred.username,
        user_cred.password
    )

    if not user:
        raise HTTPException(
            status_code=HTTPStatus.UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user["id"] = str(user["_id"])

    access_token = Authorize.create_access_token(subject=user["username"],
                                                 expires_time=config.API_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                                                 algorithm=config.API_ALGORITHM,
                                                 user_claims={"sub": str(user["_id"]), "username": user["username"]}
                                                 )

    refresh_token = Authorize.create_refresh_token(subject=user["username"],
                                                   algorithm=config.API_ALGORITHM,
                                                   user_claims={"sub": str(user["_id"]), "username": user["username"]}
                                                   )

    # # Set the JWT cookies in the response
    # Authorize.set_access_cookies(access_token)
    # Authorize.set_refresh_cookies(refresh_token)
    # return {"msg": "Successfully login"}

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer",
            "user": user}


@auth.post('/refresh')
def refresh(Authorize: AuthJWT = Depends()):
    """
    This route is used to refresh the access token before or after the access token have expired.
    **Note:** it uses the refresh token i.e `Authorization: bearer <refresh_token>`
    """
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)

    # Authorize.set_access_cookies(new_access_token)
    # return {"msg": "The token has been refresh"}

    return {"access_token": new_access_token}


@auth.delete('/logout')
def logout(Authorize: AuthJWT = Depends()):
    """
    This route must be called inorder to logout a user from a frontend.
    Because the JWT are stored in an httponly cookie now, we cannot
    log the user out by simply deleting the cookies in the frontend.
    We need the backend to send a response to delete the cookies.
    """
    Authorize.jwt_required()

    Authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@auth.put("/add-avatar", response_model=SignupReturn, responses={401: {"model": AuthError},
                                                                 500: {"model": AuthError}})
async def add_avatar(
        avatar: UploadFile, request: Request,
        Authorize: AuthJWT = Depends()
):
    """
        This route adds or update a user avatar by accepting a image file as long as the access token in
        its header.

        - **avatar**: `required` this is a file.

       \f
       :param user_data: User input.
       """

    Authorize.jwt_required()
    try:
        auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

        if not auth:
            return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                                content={"detail": f"user not found"})

        content = await avatar.read()

        f = open(f"static/image/{avatar.filename}", "wb")
        f.write(content)
        f.close()

        ups = db_helper.update_user({"_id": auth["_id"]},
                                    {"avatar_url": f"/image/{avatar.filename}"})

    except Exception as e:
        return JSONResponse(status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
                            content={"detail": f"some internal issues\n {e}"})

    return {"status": 200, "message": "successfully updated avatar", "error": ""}


@auth.put("/update", response_model=SignupReturn,
          responses={401: {"model": AuthError}, 409: {"model": AuthError, "description": ""}})
async def update_user(
        user_data: Optional[UpdateBase] = Body(title="user update"),
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
        Update User is used to update a user. `access token needed`

        - **firstname**: `optional`
        - **lastname**: `optional`
        - **country**: `optional`
        - **location**: `optional` best in format of `city, state`
        - **bio**: `optional`
        - **avatar_url**: `optional`


       \f
       :param user_data: User input.
       """

    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found "})

    changer = {}

    if user_data.firstname:
        changer["firstname"] = user_data.firstname
    if user_data.lastname:
        changer["lastname"] = user_data.lastname
    if user_data.avatar_url:
        changer["avatar_url"] = user_data.avatar_url
    if user_data.country:
        changer["country"] = user_data.country
    if user_data.bio:
        changer["bio"] = user_data.country
    if user_data.location:
        changer["location"] = user_data.country

    if not changer:
        return {"status": 200, "message": "no change due to empty body", "error": ""}

    up = db_helper.update_user({"_id": auth["_id"]}, changer)

    if not up:
        raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="sorry some error occured while updating the user")

    return {"status": 200, "message": f"successfully updated user {auth['username']}", "error": ""}


@auth.get("/current-user", response_model=CurrentUser)
async def get_current_user(Authorize: AuthJWT = Depends()):
    """
        Current User. `access token needed`

       \f
       :param user_data: User input.
       """
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found user -- {Authorize.get_jwt_subject()} "})

    auth["avatar_url"] = config.API_URL + auth["avatar_url"]
    avatar_url = ""
    num = 0
    # if str(auth["avatar_url"]).count("//") > 1:
    #     auth["avatar_url"] = ""
    #
    auth["id"] = str(auth["_id"])

    return auth


@auth.get("/referral-code", responses={200: {"model": RefToken}, 401: {"model": AuthError}})
async def get_referral_token(Authorize: AuthJWT = Depends()):
    """
        This returns the referral token of a user. `access token needed`

    """
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    return {"token": auth.get('referral_code')}


@auth.delete("/delete", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def delete_user(Authorize: AuthJWT = Depends()):
    """
         Delete a user. This route deletes a user from the database

    """

    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    d = db_helper.delete_user({"username": auth["username"]})
    if d:
        return {"status": 200, "message": f"successfully deleted user {auth['username']}", "error": ""}

    raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="sorry some error occurred while updating the user")


@auth.post("/forget-password", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def forget_password(background_tasks: BackgroundTasks, username: EmailStr = Query(...)):
    """
        forget password flow. This route accepts an email in the username field and sends a forget password
        email to it.

       """

    user = get_user_in_db({"username": username})
    if not user:
        raise HTTPException(status_code=404,
                            detail=f"user with username {username} doesn't exist")

    g = generate_password_change_object(user["_id"])

    link = "https://brainwave-five.vercel.app"

    message = MessageSchema(
        subject="Reset Your Password - Action Required",
        recipients=[username],
        template_body={
            "app_name": "brainwave",
            "title": "Verify password",
            "firstname": user["firstname"],
            "link": "https://brainwave-five.vercel.app/new-password" + f"?upt={g['token']}",
            "button_title": "Reset Password",
            "support_email": "salman2019@gmail.com",
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="verify-password-change.html")

    return {"status": 200, "message": f"an email has been sent to {username}", "error": ""}


@auth.post("/send_password_change_token", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def send_password_change_token(background_tasks: BackgroundTasks, Authorize: AuthJWT = Depends()):
    """
            Just like to forget password flow, sends a forget password email to it. But `access token needed`

    """

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    link = "https://brainwave-five.vercel.app"

    g = generate_password_change_object(auth["_id"])

    message = MessageSchema(
        subject="Password Change Confirmation - Action Required",
        recipients=[auth["username"]],
        template_body={
            "app_name": "brainwave",
            "title": "Verify password",
            "firstname": auth["firstname"],
            "link": f"https://brainwave-five.vercel.app/new-password?upt={g['token']}",
            "button_title": "Reset Password",
            "support_email": "salman2019@gmail.com",
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="update-password.html")

    return {"status": 200, "message": f"an email has been sent to {auth['username']}", "error": ""}


@auth.post("/update-password", response_model=SignupReturn, responses={409: {"model": AuthError},
                                                                       401: {"model": AuthError}
                                                                       })
async def update_password(background_tasks: BackgroundTasks, update_info: UpdatePassword = Body(...)):
    """
    This API endpoint allows users to update their password. The endpoint requires authentication and accepts a POST request.

    - **token**: `required` The authentication token for the user.
    - **new_password**: `required` The new password to be set.

    """

    check_cache = db_helper.get_from_cache(update_info.token)

    if not check_cache:
        raise HTTPException(status_code=401, detail="token has expired or is invalid")
    else:
        cache.r.expire("runner", timedelta(seconds=1))
        db_helper.update_user({"_id": check_cache["user_id"]},
                              {"password": get_password_hash(update_info.new_password)})
        u = get_user_by_id(check_cache["user_id"])

    message = MessageSchema(
        subject="Successfully Updated Your Password!",
        recipients=[u["username"]],
        template_body={
            "app_name": "brainwave",
            "title": "password change",
            "firstname": u["firstname"],
            "support_email": "salman2019@gmail.com",
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="success-password-change.html")

    return {"status": 200, "message": "successfully updated password", "error": ""}


@auth.post("/complete-verification", response_model=SignupReturn, responses={409: {"model": AuthError},
                                                                       401: {"model": AuthError}
                                                                       })
async def complete_verification(background_tasks: BackgroundTasks, verify_token: str = Query(...)):
    """
    This API endpoint is used to complete the verification process for a user.

    It expects the following parameter:

    - **verify_token**: `required` A string parameter representing the verification token associated with the user.

    """

    pass









# ------------------------ ADMIN ------------------------------

@auth.post("/admin/upgrade", response_model=SignupReturn)
async def upgrade_to_admin(
        data: AdminUpgrade,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    This route allows for the upgrade of user to a sub_admin. It accepts a json object containing
    either an `id` or  `username`. upgrade is allowed base on privilege level i.e

    `
        super_admin > sub_admin > general user
    `
    """
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    id = data.id
    username = data.username
    if auth["super_admin"] and auth["sub_admin"]:
        q = confirm_admin_body_legit(id, username)

        up = db_helper.update_user(q, {"sub_admin": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail=f"internal issue {up}")

        return {"status": 200, "message": f"successfully updated user {q.get('username') or q.get('_id')}", "error": ""}

    raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                        detail="you need super admin privileges to access this route")


@auth.post("/admin/downgrade", response_model=SignupReturn)
async def downgrade_from_admin(
        data: AdminDowngrade,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    This route allows for the downgrade of user from a sub_admin. It accepts a json object containing
    either an `id` or  `username`. downgrade is allowed base on privilege level i.e

    `
        super_admin > sub_admin > general user
    `
    """
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    id = data.id
    username = data.username
    if auth["super_admin"] and auth["sub_admin"]:
        q = confirm_admin_body_legit(id, username)

        up = db_helper.update_user(q, {"sub_admin": False})

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
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    This route allows for the blockage of user. It accepts a json object containing
    either an `id` or  `username`. blocking is allowed base on privilege level i.e
    `
        super_admin > sub_admin > general user
    `
    """
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    id = data.id
    username = data.username

    by_id = get_user_by_id(id)
    by_username = get_user_in_db({"username": data.username})

    q = {}
    user = {}
    if not by_id and not by_username:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND,
                            detail=f"user with id {id} or username {username} not found")
    if by_id:
        q = {"_id": str(by_id["_id"])}
        user = by_id
    else:
        q = {"username": str(username)}
        user = by_username

    if not user["sub_admin"] and auth["sub_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, {"disabled": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully blocked user {user['username']}", "error": ""}

    elif user["sub_admin"] and auth["super_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, {"disabled": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully blocked user {user['username']}", "error": ""}

    else:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="you do not have the authority to block this user")


@auth.post("/admin/user-list", response_model=AdminUserList)
async def user_list(
        limit: int = Query(gt=0, ),
        page: int = Query(gt=0),
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    is_admin = auth["sub_admin"]
    if not is_admin:
        raise HTTPException(status_code=401, detail="not authorised")

    u = db_helper.skiplimit({}, db.db["user"], page_size=limit, page_num=page)
    total = db_helper.get_total({}, db.db["user"])

    h = []
    if u:
        for i in u:
            i["id"] = i["_id"]
            if i["sub_admin"] or i["super_admin"]:
                i["group"] = "admin"
            else:
                i["group"] = "user"
            h.append(i)

    ret = {
        "users": h,
        "limit": limit,
        "page": page,
        "total": total
    }

    return ret


# ------------------------ END ADMIN ------------------------------

