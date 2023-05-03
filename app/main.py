from fastapi import FastAPI, HTTPException

from starlette.middleware.cors import CORSMiddleware


from fastapi.staticfiles import StaticFiles

from app.core import auth
from app.routes import views

DESCRIPTION = """
## Auth guidelines

An initial signup should be done to create a user `/user/signup`. Then followed by a login at `/user/login` to get access token
  
"""

app = FastAPI(title="Brainwave Api", version="0.1.7", description=DESCRIPTION)


# Set all CORS enabled origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(views.router)
app.include_router(auth.auth)
app.include_router(views.cdn)


