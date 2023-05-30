from pydantic import BaseModel


from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException


from app.core import config

import stripe

stripe.api_key = config.STRIPE_API_KEY




class AuthSettings(BaseModel):
    authjwt_secret_key: str = config.API_SECRET_KEY
    # Configure application to store and get JWT from cookies
    authjwt_token_location: set = {"cookies"}
    # Only allow JWT cookies to be sent over https
    # authjwt_cookie_secure: bool = False
    # Disable CSRF Protection for this example. default is True
    authjwt_cookie_csrf_protect: bool = False


@AuthJWT.load_config
def get_config():
    return AuthSettings()

