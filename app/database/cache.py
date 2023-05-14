import redis

from datetime import timedelta


r = redis.Redis(
    host="localhost",
    port=6379
)

