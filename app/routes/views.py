from __future__ import annotations
import sys

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Body
from fastapi.responses import FileResponse, JSONResponse

from pydantic import BaseModel
from fastapi_health import health
from http import HTTPStatus
from loguru import logger

from app.apis.api_a.mainmod import main_func as main_func_a
from app.core.auth import get_current_user
from app.database.db import client
from app.database.cache import r
from app.utils import get_unix_time


router = APIRouter(tags=["Welcome ✋"])

class IndexReturn(BaseModel):
    info: str


@router.get("/", responses={200: {"model": IndexReturn}})
async def index(request: Request):

    return JSONResponse(status_code=HTTPStatus.OK,
                        content={
                            "info": "This is the index page of brainwave v1 api. "
                                    "You probably want to go to 'http://<hostname:port>/docs' or 'http://<hostname:port>/redoc'",
                        })


@router.get("/dummy/{num}")
async def dummy(
        num: int = 20,
        auth: Depends = Depends(get_current_user),
) -> dict[str, int]:
    return main_func_a(num)


def database_check():
    check = client.server_info()
    if check.get("ok") == 1:
        return {
            "database": {
                "status": "online",
                "ok": check.get("ok")
            }
        }
    else:
        return {
            "database": {
                "status": "offline",
                "status_code": check.get("ok")
            }
        }


def cache_check():
    try:
        stat = r.ping()
        if stat:
            return {
                "cache": {
                    "status": "online",
                }
            }
    except Exception as e:
        print(e)
        return {
            "cache": {
                "status": "offline",
            }
        }

    # if client.server_info().get("ok") != 1:
    #     return {
    #         "database": {
    #             "status": "down"
    #         }
    #     }
    # else:
    #     return {
    #         "database": {
    #             "status": "up"
    #         }
    #     }


def more_check():
    """
    "uptime": The duration or timestamp indicating how long the API has been running without restarting.
"version": The version number or identifier of the API.
"dependencies": Information about any external services or dependencies the API relies on and their health status.
"timestamp": The
    """

    return {
        "timestamp": get_unix_time(),
        "version": "v1",
        "uptime": get_unix_time() - 89000 - 89000
    }


router.add_api_route("/health", health([database_check, cache_check, more_check]), summary="Health")

cdn = APIRouter(tags=["Micro CDN"])


@cdn.get('/image/{image}')
async def ret_images(image: str):
    try:
        open(f"static/image/{image}")
    except:
        raise HTTPException(status_code=409, detail="image not passed correctly")
    else:
        return FileResponse(f"static/image/{image}")
