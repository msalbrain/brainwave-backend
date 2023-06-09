from app.core.auth import *
from app.core.schema import AdminUserDetail, AdminUpdate, AdminUserDetailReturn


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

@admin.post("/update-user", response_model=SignupReturn)
async def update_user(
        user_id: AdminUserDetail,
        user_info: AdminUpdate,
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
    Authorize.jwt_required()
    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    id = user_id.id
    username = user_id.username

    by_id = get_user_by_id(id)
    by_username = get_user_in_db({"username": user_id.username})

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

        up = db_helper.update_user(q, user_info.dict())

        if not up:
            raise HTTPException(status_code=HTTPStatus.CONFLICT,
                                detail="internal error. Contact developer")

        return {"status": 200, "message": f"successfully updated user {user['username']}", "error": ""}

    elif user["sub_admin"] and auth["super_admin"] and not auth["disabled"]:

        up = db_helper.update_user(q, {"disabled": True})

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