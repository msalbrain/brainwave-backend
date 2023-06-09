from .db import db, user_col, log_col
from .cache import r
from app.utils import get_unix_time


from datetime import timedelta
import pickle

from fastapi import Request

ActivityUserCreated = 10010
ActivityGoogleUserCreated = 10011
ActivityUserCompleteVerification = 10010
ActivityUserLogin = 10020
ActivityGoogleUserLogin = 10021
ActivityUserDeleted = 10030
ActivityUserUpdated = 10040
ActivityUserAvatarChange = 10050
ActivityUserLogout = 10060
ActivityUserRequestPasswordChange = 10070
ActivityUserPasswordChange = 10080

ActivityAdminUpgrade = 20010
ActivityAdminDowngrade = 20020
ActivityAdminblock = 20030
ActivityAdminUpdateUser = 20040
ActivityAdminDeleteUser = 20050
ActivityAdminUserList = 20060
ActivityAdminUserDetail = 20070
ActivityAdminUserCreate = 20080

ActivityCustomerCreated = 30010

ActivityGetPaymentPage = 30020





def user_activity_log(
        activity_id,
        user_id,
        username,
        activity_type,
        activity_details,
        request: Request
):

    d = {
        "timestamp": get_unix_time(),
        "activity_id": activity_id,
        "user_id": user_id,
        "username": username,
        "activity_type": activity_type,
        "activity_details": activity_details,
        "ip_address": request.client.host,
        "user_agent": request.headers.get("user-agent")
    }

    l = log_col.insert_one(d)

    return l.inserted_id


