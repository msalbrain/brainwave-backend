from app.core.auth import *

admin_payment = APIRouter(prefix="/admin", tags=["Admin Payment"])

@admin_payment.post("/update-price")
async def update_price():
    pass


@admin_payment.post("/subscription_revenue")
async def update_price():
    pass



