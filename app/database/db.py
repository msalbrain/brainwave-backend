from pymongo import MongoClient

from app.core import config

client = MongoClient(config.MONGODB_URL)
db = client[config.MONGODB_DBNAME]

referral_col = db["referral"]
user_col = db["user"]
customer_col = db["customer"]



