import pathlib

from starlette.config import Config

ROOT = pathlib.Path(__file__).resolve().parent.parent  # app/
BASE_DIR = ROOT.parent  # ./

config = Config(BASE_DIR / ".env")

API_URL = config("API_URL", str)

API_USERNAME = config("API_USERNAME", str)
API_PASSWORD = config("API_PASSWORD", str)

# Auth configs.
API_SECRET_KEY = config("API_SECRET_KEY", str)
API_ALGORITHM = config("API_ALGORITHM", str)
API_ACCESS_TOKEN_EXPIRE_MINUTES = config(
    "API_ACCESS_TOKEN_EXPIRE_MINUTES", int
)
API_REFRESH_TOKEN_EXPIRE_MINUTES = config(
    "API_ACCESS_TOKEN_EXPIRE_MINUTES", int
)

USER_DEFAULT_IMAGE = config("USER_DEFAULT_IMAGE", str)

# Mongo config
MONGODB_URL = config("MONGODB_URL", str)
MONGODB_DBNAME = config("MONGODB_DBNAME", str)


# Mail config
MAIL_USERNAME = config("MAIL_USERNAME", str)
MAIL_PASSWORD = config("MAIL_PASSWORD", str)
MAIL_FROM = config("MAIL_FROM", str)
MAIL_PORT = config("MAIL_PORT", int)
MAIL_SERVER = config("MAIL_SERVER", str)
MAIL_FROM_NAME = config("MAIL_FROM_NAME", str)
MAIL_STARTTLS = config("MAIL_STARTTLS", bool)
MAIL_SSL_TLS = config("MAIL_SSL_TLS", bool)
USE_CREDENTIALS = config("USE_CREDENTIALS", bool)
VALIDATE_CERTS = config("VALIDATE_CERTS", bool)
