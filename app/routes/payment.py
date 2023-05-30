from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Query, Body
from http import HTTPStatus
from fastapi.responses import FileResponse, JSONResponse
from fastapi_jwt_auth import AuthJWT
from pydantic import BaseModel

from app.core.schema import CreateCheckoutSession, CreateCheckoutSessionOut, CustomerPortal, CustomerPortalOut
from app.core import config

from app.database.helpers import get_user_in_db

from app.core.dependency import stripe

from typing import Any





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

@payment.post("/create-checkout-session", response_model=CreateCheckoutSessionOut)
async def create_checkout_session(data: CreateCheckoutSession, Authorize: AuthJWT = Depends()):
    """
    ## `AccessToken Required`
    instructions for how flow works can be found here [Stripe quickstart](https://stripe.com/docs/billing/quickstart)
    - **Differences**:
         In place of a `form`, make an api request with the access token and a json object containing
        ```
        {lookup_key: "LOOKUP_KEY"}
        ```
        And you will receive a response of form
        ```
        {
          status: 0,
          redirect_url: "http://example.com"
        }
        ```
    """

    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    if not auth["customer_id"]:
        raise HTTPException(
            status_code=401,
            detail="Please complete the verification process to access this resource, check your email for "
                   "verification link"
        )

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
        success_url=config.API_URL + '?success=true',
        cancel_url=config.API_URL + '?canceled=true',
        customer=auth["customer_id"]
    )

    return {"status": 200, "redirect_url": checkout_session.url}
    # return RedirectResponse(checkout_session.url)


@payment.post('/create-portal-session', response_model=CustomerPortalOut)
async def customer_portal(data: CustomerPortal, Authorize: AuthJWT = Depends()):
    """
    ## `AccessToken Required`
    instructions for how flow works can be found here [Stripe quickstart](https://stripe.com/docs/billing/quickstart)
    - **Differences**:
         In place of a `form` and `session_id`, make an api request with the access token and a json object containing
        ```
        {return_url: "https://brainwave-five.vercel.app"}
        ```
        And you will receive a response of form
        ```
        {
          status: 0,
          redirect_url: "http://example.com"
        }
        ```
    """

    Authorize.jwt_required()

    auth = get_user_in_db({"_id": Authorize.get_jwt_subject()})

    if not auth:
        return JSONResponse(status_code=HTTPStatus.UNAUTHORIZED,
                            content={"detail": f"user not found"})

    if not auth["customer_id"]:
        raise HTTPException(
            status_code=401,
            detail="Please complete the verification process, check your email for your"
                   "verification link"
        )

    cus = stripe.Customer.retrieve(auth["customer_id"])

    portalSession = stripe.billing_portal.Session.create(
        customer=cus,
        return_url=data.return_url
    )

    return {"status": 200, "redirect_url": portalSession.url}
    # return RedirectResponse(portalSession.url, status_code=303)


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


