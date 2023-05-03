from .db import db

user = db['user']


def get_user(fields):
    return user.find_one(fields)


def update_user(query, new_values) -> bool:
    u = user.update_one(query, {"$set": new_values})

    if u.raw_result:
        return True
    return False

