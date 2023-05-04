from .db import db

user = db['user']


def get_user(fields):
    print("this is from print function")
    return user.find_one(fields)


def update_user(query, new_values) -> bool:
    u = user.update_one(query, {"$set": new_values})

    if u.raw_result:
        return True
    return False

def delete_user(filter):

    u = user.delete_one(filter)

    if u.raw_result:
        return True
    return False
