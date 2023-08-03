from pathlib import Path
from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType

from fastapi import FastAPI
from starlette.responses import JSONResponse
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig, MessageType
from pydantic import EmailStr, BaseModel
from typing import List, Any

from app.core import config

conf = ConnectionConfig(
    MAIL_USERNAME=config.MAIL_USERNAME,
    MAIL_PASSWORD=config.MAIL_PASSWORD,
    MAIL_FROM=config.MAIL_FROM,
    MAIL_PORT=config.MAIL_PORT,
    MAIL_SERVER=config.MAIL_SERVER,
    MAIL_FROM_NAME=config.MAIL_FROM_NAME,
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=True,
    TEMPLATE_FOLDER=Path(__file__).parent / '../template/mail'
)






# @app.get("/email")
# async def simple_send() -> JSONResponse:
#     html = """<p>Hi this test mail, thanks for using Fastapi-mail</p> """
#
#     message = MessageSchema(
#         subject="Fastapi-Mail module",
#         recipients=["salmanmusa2019@gmail.com"],
#         template_body=,
#         subtype=MessageType.html)
#
#     fm = FastMail(conf)
#     await fm.send_message(message)
#     return JSONResponse(status_code=200, content={"message": "email has been sent"})
