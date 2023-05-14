from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi_health import health
from http import HTTPStatus
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
import stripe

from app.apis.api_a.mainmod import main_func as main_func_a
from app.core.auth import get_current_user
from app.core.schema import IndexReturn
from app.database.db import client

from typing import Any

stripe.api_key = 'sk_test_51N4V4PG5WGB1ayF3LEVhX9LKhZXagEfS3TTLb5YCquyuhkrvOxXYa9fAR8xbwK9p8lLwHhct8LuWaNyB8PQkUwre00drxEvUiX'

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
    return {
        "cache": {
            "status": "offline"
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


router.add_api_route("/health", health([database_check, cache_check]))

cdn = APIRouter(tags=["Micro CDN"])


@cdn.get('/image/{image}')
async def ret_images(image: str):
    try:
        open(f"static/image/{image}")
    except:
        raise HTTPException(status_code=409, detail="image not passed correctly")
    else:
        return FileResponse(f"static/image/{image}")


payment = APIRouter(tags=["PAYMENT"])


class Item(BaseModel):
    type: str  # `month` or `year`
    payment_plan: str  # `pro` or `enterprise`


def calculate_order_amount(item: Item):

    p = {}
    if item.type == "year" and item.payment_plan == "pro":
        p["price"] = 999
    elif item.type == "year" and item.payment_plan == "enterprise":
        p["price"] = 2399
    elif item.type == "month" and item.payment_plan == "pro":
        p["price"] = 89
    elif item.type == "month" and item.payment_plan == "enterprise":
        p["price"] = 399
    else:
        raise HTTPException(status_code=400, detail="invalid payment plan or type")

    return p

@payment.post("/create-payment-intent")
def create_payment(
        item: Item,
        auth: Depends = Depends(get_current_user)):

    intent = stripe.PaymentIntent.create(
        amount=calculate_order_amount(item),
        currency='usd',
        automatic_payment_methods={
            'enabled': True,
        },
    )

    return {
            'clientSecret': intent['client_secret']
        }


@payment.post("/stripe-event")
async def stripe_event(
        item: Any,
        request: Request,
        auth: Depends = Depends(get_current_user)):

        event = None
        try:
            payload = await request.json()
        except:
            HTTPException(status_code=400, detail="issues receiving webhook event")

        endpoint_secret = "vftyujnbvftyuj"

        if endpoint_secret:
            # Only verify the event if there is an endpoint secret defined
            # Otherwise use the basic event deserialized with json
            sig_header = request.headers.get('stripe-signature')
            # try:
                # event = stripe.Webhook.construct_event(
                #     payload, sig_header, endpoint_secret
                # )
            # except stripe.error.SignatureVerificationError as e:
            #     print('⚠️  Webhook signature verification failed.' + str(e))
            #     return jsonify(success=False)

        # Handle the event
        if event and event['type'] == 'payment_intent.succeeded':
            payment_intent = event['data']['object']  # contains a stripe.PaymentIntent
            print('Payment for {} succeeded'.format(payment_intent['amount']))
            # Then define and call a method to handle the successful payment intent.
            # handle_payment_intent_succeeded(payment_intent)
        elif event['type'] == 'payment_method.attached':
            payment_method = event['data']['object']  # contains a stripe.PaymentMethod
            # Then define and call a method to handle the successful attachment of a PaymentMethod.
            # handle_payment_method_attached(payment_method)
        else:
            # Unexpected event type
            print('Unhandled event type {}'.format(event['type']))

        return {"success": False}

