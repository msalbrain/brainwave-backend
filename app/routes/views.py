from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import RedirectResponse
from fastapi_health import health
from http import HTTPStatus
from fastapi.responses import FileResponse, JSONResponse
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel


from app.apis.api_a.mainmod import main_func as main_func_a
from app.core.auth import get_current_user
from app.core.schema import IndexReturn, CreateCheckoutSession, SignupReturn
from app.core import config
from app.database.db import client
from app.database.cache import r
from app.database.helpers import get_user_in_db
from app.utils import get_unix_time
from app.core.dependency import stripe


from typing import Any


router = APIRouter(tags=["Welcome ✋"])


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


payment = APIRouter(tags=["Payment"])


class Item(BaseModel):
    type: str  # `month` or `year`
    payment_plan: str  # `pro` or `enterprise`


# def calculate_order_amount(item: Item):
#     p = {}
#     if item.type == "year" and item.payment_plan == "pro":
#         p["price"] = 999
#     elif item.type == "year" and item.payment_plan == "enterprise":
#         p["price"] = 2399
#     elif item.type == "month" and item.payment_plan == "pro":
#         p["price"] = 89
#     elif item.type == "month" and item.payment_plan == "enterprise":
#         p["price"] = 399
#     else:
#         raise HTTPException(status_code=400, detail="invalid payment plan or type")
#
#     return p


# @payment.post("/create-payment-intent")
# def create_payment(
#         item: Item,
#         auth: Depends = Depends(get_current_user)):
#     intent = stripe.PaymentIntent.create(
#         amount=calculate_order_amount(item),
#         currency='usd',
#         automatic_payment_methods={
#             'enabled': True,
#         },
#     )
#
#     return {
#         'clientSecret': intent['client_secret']
#     }

@payment.post("/create-checkout-session")
async def create_checkout_session(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    prices = stripe.Price.list(
        lookup_keys=[data.lookup_key],
        expand=['data.product']
    )

    checkout_session = stripe.checkout.Session.create(
        line_items=[
            {
                'price': prices.data[0].id,
                'quantity': 1,
            },
        ],
        mode='subscription',
        success_url=config.API_URL +
                    '?success=true',
        cancel_url=config.API_URL + '?canceled=true',
    )

    return {"status": 200, "redirect_url": checkout_session.url}
    # return RedirectResponse(checkout_session.url)


@payment.post('/create-portal-session')
async def customer_portal(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    cus = stripe.Customer.retrieve("")

    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    return_url = config.API_URL

    portalSession = stripe.billing_portal.Session.create(
        customer=cus,
        return_url=return_url,
    )

    return RedirectResponse(portalSession.url, status_code=303)


@payment.post('/webhook', include_in_schema=False)
async def webhook_received(request: Request):
    webhook_secret = config.STRIPE_WEBHOOK_KEY
    request_data = await request.json()

    event: Any = object

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')

        try:
            event = stripe.Webhook.construct_event(
                payload=request_data, sig_header=signature, secret=webhook_secret)
            data = event['data']
        except Exception as e:
            return e
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request_data
        event_type = request_data

    print('event ' + event_type)

    if event_type == 'checkout.session.completed':
        print('🔔 Payment succeeded!')
    elif event_type == 'customer.subscription.trial_will_end':
        print('Subscription trial will end')
    elif event_type == 'customer.subscription.created':
        print('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.updated':
        print('Subscription created %s', event.id)
    elif event_type == 'customer.subscription.deleted':
        print('Subscription canceled: %s', event.id)

    return {'status': 'success'}


analytics = APIRouter(tags=["Analytics"])


@analytics.get('/analytics/user')
async def analytics_by_user_id(Authorize: AuthJWT = Depends(), user_id: str = Query(...)):
    """
    `PENDING`
    This endpoint retrieves the analytics data for a specific user identified by user_id.
    The response may include information such as user engagement, activity history, preferences, and other relevant metrics.
    """
    pass


@analytics.get('/analytics/conversion-rates')
async def conversion_rates(Authorize: AuthJWT = Depends()):
    """
    `PENDING`
    This endpoint retrieves the conversion rates for specific actions or events, such as sign-ups and subscriptions.
     It helps analyze the effectiveness of conversion funnels and identify areas for improvement.
    """
    pass


@analytics.get('/analytics/user-retention')
async def user_retention(Authorize: AuthJWT = Depends()):
    """
    `PENDING`
    This endpoint provides information about user retention rates over time.
    It allows tracking the percentage of users who continue to engage with the application after a specific period, helping measure user loyalty and satisfaction.
    """
    pass


@analytics.get('/analytics/geographic-insights')
async def geographic_insights(Authorize: AuthJWT = Depends()):
    """
    `PENDING`
    This endpoint provides geographic insights about user distribution, allowing analysis of user engagement and preferences based on geographical location.
    It helps tailor content, marketing strategies, or localization efforts.
    """
    pass
