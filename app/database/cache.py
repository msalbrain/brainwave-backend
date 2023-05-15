import redis
from app.core import config

from datetime import timedelta


r = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT
)

