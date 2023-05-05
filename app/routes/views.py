from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from http import HTTPStatus
from fastapi.responses import FileResponse, JSONResponse

from app.apis.api_a.mainmod import main_func as main_func_a
from app.core.auth import get_current_user
from app.core.schema import IndexReturn

router = APIRouter(tags=["General Routes"])


@router.get("/", responses={200: {"model": IndexReturn}})
async def index():
    return JSONResponse(status_code=HTTPStatus.OK,
                        content={
                            "info": "This is the index page of fastapi-nano. "
                                    "You probably want to go to 'http://<hostname:port>/docs'.",
                        })


@router.get("/dummy/{num}")
async def dummy(
        num: int = 20,
        auth: Depends = Depends(get_current_user),
) -> dict[str, int]:
    return main_func_a(num)




cdn = APIRouter(tags=["Micro CDN"])


@cdn.get('/image/{image}')
def ret_images(image: str):
    try:
        open(f"static/image/{image}")
    except:
        raise HTTPException(status_code=409, detail="image not passed correctly")
    else:
        return FileResponse(f"static/image/{image}")
