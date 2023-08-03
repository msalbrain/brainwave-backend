from .db import db
from .cache import r

from datetime import timedelta
from pprint import pprint
import pickle

user = db['user']


def get_user_in_db(fields):
    return user.find_one(fields)


def update_user(query, new_values) -> bool:
    u = user.update_one(query, {"$set": new_values})

    return u

def update_user_array(query, values: dict, add=True) -> bool:
    u = user.find_one(query)

    if add:
        updated_fields = {}
        for i in values.items():
            if u[i[0]]:
                if not isinstance(i[1], list):
                    raise Exception("not array")
                u[i[0]].extend(i[1])
            updated_fields[i[0]] = list(set(u[i[0]]))
        pprint(updated_fields)
        up_add = user.update_one(query, {"$set": updated_fields})
        return up_add
    if not add:
        pass

    return u


def delete_user(filter):
    u = user.delete_one(filter)

    return u.raw_result


def skiplimit(query, coll, page_size, page_num):
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
    total = db["user"].count_documents({})

    return total


def add_to_cache(data, key, exp=10):
    if type(data) == type({}):
        data = pickle.dumps(data)

    return r.setex(
        key,
        timedelta(minutes=exp),
        value=data
    )


def get_from_cache(key):
    return pickle.loads(r.get(key))
