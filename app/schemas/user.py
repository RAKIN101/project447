from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class RegistrationInput(BaseModel):
    full_name: str = Field(min_length=2, max_length=120)
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    phone: str = Field(max_length=40)
    address: str = Field(max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["Citizen", "Admin"] = "Citizen"
