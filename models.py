from pydantic import BaseModel, Field

class User(BaseModel):
    email: str
    doc_number: str
    password: str
    username: str
    fullname: str

class PasswordRecovery(BaseModel):
    email: str
    document: str = Field(..., alias="document")
    new_password: str

    class Config:
        allow_population_by_field_name = True

class Login(BaseModel):
    login: str = Field(..., alias="login")
    password: str

    class Config:
        allow_population_by_field_name = True