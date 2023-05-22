from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from fastapi.responses import RedirectResponse
from fastapi_health import health
from http import HTTPStatus
from fastapi.responses import FileResponse, JSONResponse
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel
import stripe

from app.apis.api_a.mainmod import main_func as main_func_a
from app.core.auth import get_current_user
from app.core.schema import IndexReturn, CreateCheckoutSession, SignupReturn
from app.core import config
from app.database.db import client
from app.database.cache import r
from app.database.helpers import get_user_in_db

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


router.add_api_route("/health", health([database_check, cache_check]), summary="Health")

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
                    '?success=true&session_id={CHECKOUT_SESSION_ID}',
        cancel_url=config.API_URL + '?canceled=true',
    )
    return RedirectResponse(checkout_session.url)


@payment.post('/create-portal-session')
async def customer_portal(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    checkout_session = stripe.checkout.Session.retrieve(auth["_id"])

    # This is the URL to which the customer will be redirected after they are
    # done managing their billing with the portal.
    return_url = config.API_URL

    portalSession = stripe.billing_portal.Session.create(
        customer=checkout_session.customer,
        return_url=return_url,
    )

    return RedirectResponse(portalSession.url, status_code=303)


@payment.post('/webhook')
async def webhook_received(request: Request):
    webhook_secret = 'whsec_12345'
    request_data = request.json()

    event: Any = object()

    if webhook_secret:
        # Retrieve the event by verifying the signature using the raw body and secret if webhook signing is configured.
        signature = request.headers.get('stripe-signature')

        try:
            event = stripe.Webhook.construct_event(
                payload=request.json(), sig_header=signature, secret=webhook_secret)
            data = event['data']
        except Exception as e:
            return e
        # Get the type of webhook event sent - used to check the status of PaymentIntents.
        event_type = event['type']
    else:
        data = request.json()
        event_type = request.json()
    data_object = data['object']

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
async def analytics_by_user_id(data: CreateCheckoutSession, Authorize: AuthJWT = Depends(), user_id: str = Query(...)):
    """
    This endpoint retrieves the analytics data for a specific user identified by user_id.
    The response may include information such as user engagement, activity history, preferences, and other relevant metrics.
    """
    pass


@analytics.get('/analytics/conversion-rates')
async def conversion_rates(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    """
    This endpoint retrieves the conversion rates for specific actions or events, such as sign-ups and subscriptions.
     It helps analyze the effectiveness of conversion funnels and identify areas for improvement.
    """
    pass



@analytics.get('/analytics/user-retention')
async def user_retention(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    """
    This endpoint provides information about user retention rates over time.
    It allows tracking the percentage of users who continue to engage with the application after a specific period, helping measure user loyalty and satisfaction.
    """
    pass


@analytics.get('/analytics/geographic-insights')
async def geographic_insights(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    """
    This endpoint provides geographic insights about user distribution, allowing analysis of user engagement and preferences based on geographical location.
    It helps tailor content, marketing strategies, or localization efforts.
    """
    pass


