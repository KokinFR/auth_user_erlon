from pydantic import BaseModel, Field

class User(BaseModel):
    email: str
    doc_number: str
    password: str
    username: str
    fullname: str



class PasswordResetResq(BaseModel):
    email: str
    document: str = Field(..., alias="document")

    class Config:
        allow_population_by_field_name = True

class PasswordConfirm(BaseModel):
    token: str
    new_password: str

class Login(BaseModel):
    login: str = Field(..., alias="login")
    password: str

    class Config:
        allow_population_by_field_name = True