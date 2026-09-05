from pydantic import BaseModel, Field


class PostInput(BaseModel):
    title: str = Field(min_length=3, max_length=160)
    content: str = Field(min_length=1, max_length=5000)
