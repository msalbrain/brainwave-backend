from app.core.auth import *
from app.core.schema.admin import AdminUserDetail, AdminUpdate, AdminUserDetailReturn, AdminCreateNewUser, \
    AdminUpgrade, AdminDowngrade, AdminBlock, AdminUserList

admin = APIRouter(prefix="/admin", tags=["Admin"])


@admin.post("/upgrade", response_model=SignupReturn)
async def upgrade_to_admin(
        data: AdminUpgrade,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
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


@admin.post("/downgrade", response_model=SignupReturn)
async def downgrade_from_admin(
        data: AdminDowngrade,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
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


@admin.post("/block", response_model=SignupReturn)
async def block_user(
        data: AdminBlock,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
    This route allows for the blockage of user. It accepts a json object containing
    either an `id` or  `username`. blocking is allowed base on privilege level i.e
    `
        super_admin > sub_admin > general user
    `
    """
    is_block = "block"
    if not data.block:
        is_block = "unblocked"
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

        up = db_helper.update_user(q, {"disabled": data.block})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully {is_block} user {user['username']}", "error": ""}

    elif user["sub_admin"] and auth["super_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, {"disabled": data.block})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully {is_block} user {user['username']}", "error": ""}

    else:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="you do not have the authority to block this user")


@admin.put("/update-user", response_model=SignupReturn)
async def update_user(
        user_info: AdminUpdate,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
    This route allows for the updating a user. It accepts a json object containing
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

    id = user_info.id
    username = user_info.username

    by_id = get_user_by_id(id)
    by_username = get_user_in_db({"username": user_info.username})

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

    up_dict = {}
    if user_info.firstname:
        up_dict["firstname"] = user_info.firstname
    if user_info.lastname:
        up_dict["lastname"] = user_info.lastname
    if user_info.bio:
        up_dict["bio"] = user_info.bio
    if user_info.location:
        up_dict["location"] = user_info.location
    if user_info.country:
        up_dict["country"] = user_info.country

    if not user["sub_admin"] and auth["sub_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, up_dict)

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully updated user {user['username']}", "error": ""}

    elif user["sub_admin"] and auth["super_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, up_dict)

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully updated user {user['username']}", "error": ""}

    else:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="you do not have the authority to update this user")


@admin.post("/delete", response_model=SignupReturn)
async def delete_user(
        data: AdminUserDetail,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
    This route allows for the deletion of user. It accepts a json object containing
    either an `id` or  `username`. deleting is allowed base on privilege level i.e
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

        up = db_helper.user.delete_one(q)

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully deleted user {user['username']}", "error": ""}

    elif user["sub_admin"] and auth["super_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, {"disabled": True})

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully deleted user {user['username']}", "error": ""}

    else:
        raise HTTPException(status_code=HTTPStatus.UNAUTHORIZED,
                            detail="you do not have the authority to delete this user")


@admin.post("/user-list", response_model=AdminUserList)
async def user_list(
        limit: int = Query(gt=0, ),
        page: int = Query(gt=0),
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
    This endpoint returns a list of users.

    """
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


@admin.post("/user-detail", response_model=AdminUserDetailReturn)
async def get_user_detail(
        data: AdminUpgrade,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
    ## `AccessToken Required`
    This endpoint is only available to admins. It requires the user `id` or `username`

    **Note**: Any parameter not being used shouldn't be added.

    - **id**: `optional` this is used to identify the user to be updated. it can be skipped but `username` nust be present
    - **username**: `optional` this is used to identify the user to be updated. it can be skipped but `id` nust be present
    - **firstname**: `optional` the user's firstname.
    - **lastname**: `optional` the user's lastname.
    - **country**: `optional` the user's country.
    - **location**: `optional` the user's location.
    - **bio**: `optional` the user's bio.

    """

    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    is_admin = auth["sub_admin"]
    if not is_admin:
        raise HTTPException(status_code=401, detail="not authorised")

    q = {}
    if data.id:
        q = {"_id": data.id}
    elif data.username:
        q = {"username": data.username}

    user_obj = get_user_in_db(q)

    if not user_obj:
        raise HTTPException(status_code=404, detail="user not found")

    else:
        if str(user_obj["avatar_url"]).startswith("http"):
            pass
        else:
            user_obj["avatar_url"] = config.API_URL + user_obj["avatar_url"]

        return {
            "id": user_obj["_id"],
            "firstname": user_obj["firstname"],
            "lastname": user_obj["lastname"],
            "username": user_obj["username"],
            "bio": user_obj["bio"],
            "location": user_obj["location"],
            "avatar_url": user_obj["avatar_url"],
            "customer_id": user_obj["customer_id"],
            "referral_code": user_obj["referral_code"],
            "country": user_obj["country"],
            "disabled": user_obj["disabled"],
            "verified": user_obj["verified"],
            "super_admin": user_obj["super_admin"],
            "sub_admin": user_obj["sub_admin"],
            "subscribed": user_obj["subscribed"],
            "updated": user_obj["updated"],
            "created": user_obj["created"]
        }


@admin.post("/create-user", response_model=AdminUserDetailReturn)
async def create_new_user(
        request: Request,
        background_tasks: BackgroundTasks,
        data: AdminCreateNewUser,
        Authorize: AuthJWT = Depends()
) -> dict[str, Any] | JSONResponse:
    """
        ## `AccessToken Required`
       This is an admin only endpoint that creates a new user. This is one of the ways of initializing a new user into
       the system.
       **Note**: Any parameter not being used shouldn't be added.

        - **username**: `required` each user must be an email.
        - **password**: `required` each user must have a password.
        - **firstname**: `required` each user must have a firstname.
        - **lastname**: `required` each user must have a lastname.
        - **country**: `required` each user must have a country.
        - **avatar_url**: `optional` an image url e.g `http://image.jpg` is what should be provided. if an image object
        is what is in hand there is a route named `v1/user/add-avatar` for that (NOTE: you must signup first).
        - **bio**: `required` each item must have a bio.
        - **location**: `required` each user must have a location preferably `city, state`.
        - **referrer_id**: `optional` this field is the id of the referral. It is optional.
       \f
       :param user_data: User input.
    """

    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    is_admin = auth["sub_admin"]
    if not is_admin:
        raise HTTPException(status_code=401, detail="not authorised")

    u = get_user_in_db({"username": data.username})

    if u:
        raise HTTPException(
            status_code=409,
            detail="user already exist",
        )

    new_user_id = str(uuid4()).replace('-', '')  # generate id for new user
    ref = validate_ref(data, new_user_id)

    user = db.db["user"]
    dp_image = ""

    if data.avatar_url:
        dp_image = data.avatar_url
    else:
        dp_image = config.USER_DEFAULT_IMAGE

    t = get_unix_time()

    d = {
        "_id": new_user_id,
        "firstname": data.firstname,
        "lastname": data.lastname,
        "username": data.username,
        "bio": data.bio,
        "location": data.location,
        "avatar_url": dp_image,
        "customer_id": "",
        "referral_code": str(uuid4()).replace('-', ''),
        "list_of_referral": [],
        "list_of_verified_referral": [],
        "password": get_password_hash(data.password),
        "password_changed": {  # TODO: work the change password logic and update its object
            "last_date": t,
            "token": ""
        },
        "country": data.country,
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
    logger.user_activity_log(
        activity_id=logger.ActivityAdminUserCreate,
        user_id=d["_id"],
        username=d["username"],
        activity_type="user created",
        activity_details=f"A user with username {d['username']} and id {d['_id']} has been created by "
                         f"Admin {auth['username']}",
        request=request
    )
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
