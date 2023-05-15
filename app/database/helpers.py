from .db import db
from .cache import r

from datetime import timedelta


user = db['user']


def get_user_in_db(fields):

    return user.find_one(fields)


def update_user(query, new_values) -> bool:
    u = user.update_one(query, {"$set": new_values})

    return u


def delete_user(filter):
    u = user.delete_one(filter)

    return u.raw_result


def skiplimit(query, coll,page_size, page_num):
    """returns a set of documents belonging to page number `page_num`
    where size of each page is `page_size`.
    """
    # Calculate number of documents to skip
    skips = page_size * (page_num - 1)

    # Skip and limit
    cursor = coll.find(query).skip(skips).limit(page_size)

    # Return documents
    return [x for x in cursor]

def get_total(query, coll):
    total = db["user"].count_documents()

    return total

def add_to_cache(data, key, exp):
    return r.setex(
        key,
        timedelta(minutes=10),
        value=data
    )


def get_from_cache(key):
    return r.get(key)
