from __future__ import annotations

from uuid import uuid4

from datetime import timedelta
from http import HTTPStatus
from typing import Any, Optional, Annotated
from pydantic import EmailStr

from fastapi import APIRouter, Depends, HTTPException, UploadFile, Request, File, \
    Body, BackgroundTasks, Query, Header, status

from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType

from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from google.oauth2 import id_token
from google.auth.transport import requests
from app.core import config
from app.database import helpers as db_helper, db, cache
from app.database.db import referral_col, user_col, customer_col
from app.utils import get_random_string, get_unix_time
from .schema.auth import Token, UpdateBase, SignupReturn, SignupUser, \
    AuthError, CurrentUser, RefToken, LoginUser, \
    UpdatePassword, GoogleToken
from app.core.utils import get_password_hash, get_user_by_id, get_current_user, \
    get_user_in_db, authenticate_user, verify_user, validate_ref, \
    generate_password_change_object, validate_google_ref
from app.mail import conf
from app.core.dependency import stripe, AuthJWT

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/login")

# class AuthSettings(BaseModel):
#     authjwt_secret_key: str = config.API_SECRET_KEY
# Configure application to store and get JWT from cookies
# authjwt_token_location: set = {"cookies"}
# Disable CSRF Protection for this example. default is True
# authjwt_cookie_csrf_protect: bool = False


# @AuthJWT.load_config
# def get_config():
#     return AuthSettings()


auth = APIRouter(prefix="/user", tags=["Authentication"])


@auth.post("/signup", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def create_new_user(
        request: Request, background_tasks: BackgroundTasks, user_data: SignupUser = Body(...)
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

    new_user_id = str(uuid4()).replace('-', '')  # generate id for new user
    ref = validate_ref(user_data, new_user_id)

    user = db.db["user"]
    dp_image = ""

    if user_data.avatar_url:
        dp_image = user_data.avatar_url
    else:
        dp_image = config.USER_DEFAULT_IMAGE

    t = get_unix_time()

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

    user_obj = user.insert_one(d)

    message = MessageSchema(
        subject="Welcome to Brainwave - Confirm Your Email Address",
        recipients=[d["username"]],
        template_body={
            "app_name": "brainwave",
            "title": "New user",
            "firstname": d["firstname"],
            "support_email": "brainwave@mail.com",
            "link": f"https://brainwave-five.vercel.app?sup={new_user_id}"
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="new_user.html")

    return {"status": 200, "message": "successfully created user", "error": ""}


@auth.post("/google-signup", response_model=Token, responses={401: {"model": AuthError}})
async def google_signup(
        request: Request, access_token: GoogleToken, Authorize: AuthJWT = Depends()
) -> dict[str, Any]:
    """
        This endpoint enables google signup/login. After acquiring the access token from google on the 
        frontend 

        - **token**: `required` The access token gotten from google.
        - **referrer_id**: `optional` this field is the id of the referral. It is optional.

    """
    global lastname
    try:
        idinfo = id_token.verify_token(access_token.token, requests.Request(), config.GOOGLE_CLIENT_ID)

    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="couldn't verify credentials")

    user_exist = get_user_in_db({"_id": idinfo['sub'], "username": idinfo['email']})

    if user_exist:
        # got lazy i.e I wasn't DRY
        access_token = Authorize.create_access_token(subject=idinfo['email'],
                                                     expires_time=config.API_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                                                     algorithm=config.API_ALGORITHM,
                                                     user_claims={"sub": idinfo['sub'], "username": idinfo['email']}
                                                     )

        refresh_token = Authorize.create_refresh_token(subject=idinfo['email'],
                                                       algorithm=config.API_ALGORITHM,
                                                       user_claims={"sub": idinfo['sub'], "username": idinfo['email']}
                                                       )

        user_exist["id"] = user_exist["_id"]
        user_exist.pop("_id")

        return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer",
                "user": user_exist}


    else:
        t = get_unix_time()

        validate_google_ref(idinfo, access_token.referrer_id)

        firstname = idinfo["name"].split(" ")[0]
        if len(idinfo["name"].split(" ")) > 1:
            lastname = idinfo["name"].split(" ")[1]

        d = {
            "_id": idinfo["sub"],
            "firstname": firstname,
            "lastname": lastname,
            "username": idinfo["email"],
            "bio": "I am a user",
            "location": "",
            "avatar_url": idinfo["picture"],
            "customer_id": "",
            "referral_code": str(uuid4()).replace('-', ''),
            "list_of_referral": [],
            "list_of_verified_referral": [],
            "password": "",
            "password_changed": {  # TODO: work the change password logic and update its object
                "last_date": 0,
                "token": ""
            },
            "country": "",
            "google_id": idinfo["jti"],
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

    cus = stripe.Customer.create(
        description=d["bio"],
        email=d["username"],
        name=d["firstname"] + " " + d["lastname"]
    )

    d.update({"verified": True, "customer_id": cus["id"]})

    user = db.db["user"]
    user_obj = user.insert_one(d)

    access_token = Authorize.create_access_token(subject=idinfo['email'],
                                                 expires_time=config.API_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                                                 algorithm=config.API_ALGORITHM,
                                                 user_claims={"sub": idinfo['sub'],
                                                              "username": idinfo['email']}
                                                 )

    refresh_token = Authorize.create_refresh_token(subject=idinfo['email'],
                                                   algorithm=config.API_ALGORITHM,
                                                   user_claims={"sub": idinfo['sub'],
                                                                "username": idinfo['email']}
                                                   )

    d["id"] = d["_id"]
    d.pop("_id")
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer",
            "user": d}


@auth.post("/login", response_model=Token, responses={401: {"model": AuthError}})
async def login_for_access_token(
        request: Request, user_cred: LoginUser, Authorize: AuthJWT = Depends()
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
def refresh(request: Request, Authorize: AuthJWT = Depends()):
    """
    ## `RefreshToken Required`
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
def logout(request: Request, Authorize: AuthJWT = Depends()):
    """
    ## `AccessToken Required`
    This route must be called inorder to logout a user from a frontend.
    Because the JWT are stored in an httponly cookie now, we cannot
    log the user out by simply deleting the cookies in the frontend.
    We need the backend to send a response to delete the cookies.
    """
    # Authorize.jwt_required()

    # Authorize.unset_jwt_cookies()
    return {"msg": "Successfully logout"}


@auth.put("/add-avatar", response_model=SignupReturn, responses={401: {"model": AuthError},
                                                                 500: {"model": AuthError}})
async def add_avatar(
        request: Request,
        avatar: UploadFile,
        Authorize: AuthJWT = Depends()
):
    """
    ## `AccessToken Required`
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
        request: Request,
        user_data: Optional[UpdateBase] = Body(title="user update"),
        auth: dict[str, Any] = Depends(get_current_user)
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
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


@auth.get("/current-user", response_model=CurrentUser, operation_id="authorize")
async def get_current_user(request: Request, auth: dict[str, Any] = Depends(get_current_user)):
    """
    ## `AccessToken Required`
    Current User.

   \f
   :param user_data: User input.
    """

    if str(auth["avatar_url"]).startswith("http"):
        pass
    else:
        auth["avatar_url"] = config.API_URL + auth["avatar_url"]

    auth["id"] = str(auth["_id"])

    return auth


@auth.get("/referral-code", responses={200: {"model": RefToken}, 401: {"model": AuthError}})
async def get_referral_token(request: Request, auth: dict[str, Any] = Depends(get_current_user)):
    """
    ## `AccessToken Required`
    This returns the referral token of a user. `access token needed`

    """

    return {"token": auth.get('referral_code')}


@auth.delete("/delete", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def delete_user(request: Request, auth: dict[str, Any] = Depends(get_current_user)):
    """
    ## `AccessToken Required`
    Delete a user. This route deletes a user from the database

    """

    d = db_helper.delete_user({"username": auth["username"]})
    if d:
        return {"status": 200, "message": f"successfully deleted user {auth['username']}", "error": ""}

    raise HTTPException(status_code=HTTPStatus.CONFLICT, detail="sorry some error occurred while updating the user")


@auth.post("/forget-password", response_model=SignupReturn, responses={409: {"model": AuthError}})
async def forget_password(request: Request, background_tasks: BackgroundTasks, username: EmailStr = Query(...)):
    """
    forget password flow. This route accepts an email in the username field and sends a forgot password
    email to it.
    """

    user = get_user_in_db({"username": username})
    if not user:
        raise HTTPException(status_code=404,
                            detail=f"user with username {username} doesn't exist")
    elif user["google_id"]:
        raise HTTPException(status_code=403,
                            detail=f"user with username {username} forbidden from updating password")

    g = generate_password_change_object(user["_id"])

    link = config.APP_URL

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
async def send_password_change_token(request: Request, background_tasks: BackgroundTasks,
                                     auth: dict[str, Any] = Depends(get_current_user)):
    """
    ## `AccessToken Required`
    Just like to forget password flow, sends a forget password email to it. But `access token needed`

    """

    if auth["google_id"]:
        raise HTTPException(status_code=403,
                            detail=f"user with username {g['username']} forbidden from updating password")

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
async def update_password(request: Request, background_tasks: BackgroundTasks, update_info: UpdatePassword = Body(...)):
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
                              {"password": get_password_hash(update_info.new_password),

                               })
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


@auth.post("/complete-verification", responses={409: {"model": AuthError},
                                                401: {"model": AuthError}
                                                })
async def complete_verification(request: Request, background_tasks: BackgroundTasks, sup: str = Query(...,
                                                                                                      description="`required` A string parameter representing the verification token associated with the user.")):
    """
    This API endpoint is used to complete the verification process for a user.

    """

    u = get_user_by_id(sup)
    if not u:
        raise HTTPException(status_code=401, detail="invalid status code")

    if u["verified"]:
        return JSONResponse(
            {
                "status": 200,
                "message": "successfully verified",
                "error": ""
            }
        )

    cus = stripe.Customer.create(
        description=u["bio"],
        email=u["username"],
        name=u["firstname"] + " " + u["lastname"]
    )

    upt = db_helper.update_user({"_id": u["_id"]}, {"verified": True, "customer_id": cus["id"]})
    update_referral = verify_user(u["_id"])

    # TODO: SEND CONGRATULATION ON ACCOUNT VERIFICATION

    message = MessageSchema(
        subject="Congratulations! Your User Verification is Complete!",
        recipients=[u["username"]],
        template_body={
            "app_name": "brainwave",
            "title": "Verification is Complete!",
            "firstname": u["firstname"],
            "support_email": "brainwave@mail.com",
        }, subtype=MessageType.html)
    fm = FastMail(conf)

    # await fm.send_message(message)
    background_tasks.add_task(fm.send_message, message, template_name="complete-verification.html")

    return {
        "status": 200,
        "message": "successfully verified",
        "customer": cus
    }
