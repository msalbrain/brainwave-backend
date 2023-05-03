import random
import string
import datetime
import time


def get_random_string(length):
    # choose from all lowercase letter
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


def get_unix_time():
    date_time = datetime.datetime.utcnow()

    return time.mktime(date_time.timetuple())
