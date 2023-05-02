from .db import db

user = db['user']


def get_user(fields):
    return user.find_one(fields)


