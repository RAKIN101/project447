from pydantic import BaseModel, Field


class PaymentRequest(BaseModel):
    payment_method: str = Field(pattern="^(Mobile Banking|Card|Bank Transfer)$")
