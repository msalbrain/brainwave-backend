from pymongo import MongoClient

from app.core import config

client = MongoClient(config.MONGODB_URL)
db = client[config.MONGODB_DBNAME]


