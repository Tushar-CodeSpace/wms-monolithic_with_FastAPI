from pydantic import BaseModel, EmailStr

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class RegisterResponse(BaseModel):
    message: str = "User registered successfully"
    user_id: str
    token: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginResponse(BaseModel):
    message: str = "User logged in successfully"
    user_id: str
    token: str