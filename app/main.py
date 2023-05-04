from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi

from starlette.middleware.cors import CORSMiddleware

from app.core import auth
from app.routes import views

DESCRIPTION = """
## Auth guidelines

An initial signup should be done to create a user `/user/signup`. Then followed by a login at `/user/login` to get access token
  
"""

app = FastAPI()


app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(views.router)
app.include_router(auth.auth)
app.include_router(views.cdn)

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Brainwave API",
        version="0.1.7",
        description=DESCRIPTION,
        routes=app.routes
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "http://127.0.0.1:5000/image/logo.svg"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


