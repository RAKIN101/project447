from pydantic import BaseModel, Field


class PaymentInput(BaseModel):
    payment_method: str = Field(pattern="^(Mobile Banking|Card|Bank Transfer)$")
