from fastapi import FastAPI
from passlib.context import CryptContext
from jose import JWTError, jwt
import databases
from sqlalchemy import Column, Integer, String, DateTime, Boolean,func
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime, timedelta
from pydantic import BaseModel,EmailStr
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException, status, Form,Request
from sqlalchemy.orm import Session
from typing import Union, Any
from sqlalchemy import create_engine
from jwt import InvalidTokenError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from functools import wraps
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

app = FastAPI()


DATABASE_URL = "postgresql://postgres:root@localhost/authentication_api"
SECRET_KEY = "your-secret-key"
PASSWORD_RESET_SECRET_KEY = "your-reset-secret-key"

ALGORITHM = "HS256"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
class TokenTable(Base):
    __tablename__ = "token"
    user_id = Column(Integer)
    access_toke = Column(String(450), primary_key=True)
    refresh_toke = Column(String(450),nullable=False)
    status = Column(Boolean)
    created_date = Column(DateTime, default=func.now())


Base.metadata.create_all(bind=engine)#craeted database 
list=[]


class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class requestdetails(BaseModel):
    email:str
    password:str

class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str
    

class changepassword(BaseModel):
    email:str
    old_password:str
    new_password:str

def get_db():
    db = SessionLocal()
    try:
        yield db #yield statement is used in a generate function to temprrally yield and pass database
    finally:
        db.close()


@app.get("/user/")
async def read_user(db: Session = Depends(get_db)):
    # Use the db session to query the database
    items = db.query(User).all()
    return items

@app.post("/register")
def register_user(user: UserCreate, session: Session = Depends(get_db)):
    existing_user = session.query(User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_hashed_password(user.password)

    new_user = User(username=user.username, email=user.email, hashed_password=encrypted_password)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": "user created successfully"}

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 7 days
ALGORITHM = "HS256"
JWT_SECRET_KEY = "narscbjim@$@&^@&%^&RFghgjvbdsha"   # should be kept secret
JWT_REFRESH_SECRET_KEY = "13ugfdfgh@#$%^@&jkl45678902"

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_hashed_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, hashed_pass: str) -> bool:
    return password_context.verify(password, hashed_pass)

def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
        
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
         
    
    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
     
    return encoded_jwt

def create_refresh_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=REFRESH_TOKEN_EXPIRE_MINUTES)
    
    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_REFRESH_SECRET_KEY, ALGORITHM)
    return encoded_jwt


@app.post('/login' ,response_model=TokenSchema)
def login(request:requestdetails, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email")
    hashed_pass = user.hashed_password
    if not verify_password(request.password, hashed_pass):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )
    
    access=create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    token_db = TokenTable(user_id=user.id,  access_toke=access,  refresh_toke=refresh, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {
        "access_token": access,
        "refresh_token": refresh,
    }

def decodeJWT(jwtoken: str):
    try:
        # Decode and verify the token
        payload = jwt.decode(jwtoken, JWT_SECRET_KEY, ALGORITHM)
        return payload
    except InvalidTokenError:
        return None


class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(status_code=403, detail="Invalid token or expired token.")
            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def verify_jwt(self, jwtoken: str) -> bool:
        isTokenValid: bool = False

        try:
            payload = decodeJWT(jwtoken)
        except:
            payload = None
        if payload:
            isTokenValid = True
        return isTokenValid

jwt_bearer = JWTBearer()


@app.post('/change-password')
def change_password(request:changepassword, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    
    if not verify_password(request.old_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password")
    
    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    db.commit()
    
    return {"message": "Password changed successfully"}


@app.post('/logout')
def logout(dependencies=Depends(JWTBearer()), db: Session = Depends(get_db)):
    token=dependencies
    payload = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    user_id = payload['sub']
    token_record = db.query(TokenTable).all()
    info=[]
    for record in token_record :
        print("record",record)
        if (datetime.utcnow() - record.created_date).days >1:
            info.append(record.user_id)
    if info:
        existing_token = db.query(TokenTable).where(TokenTable.user_id.in_(info)).delete()
        db.commit()
        
    existing_token = db.query(TokenTable).filter(TokenTable.user_id == user_id,TokenTable.access_toke==token).first()
    if existing_token:
        existing_token.status=False
        db.add(existing_token)
        db.commit()
        db.refresh(existing_token)
    return {"message":"Logout Successfully"} 


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
    
        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data= kwargs['session'].query(TokenTable).filter_by(user_id=user_id,access_toke=kwargs['dependencies'],status=True).first()
        if data:
            return func(kwargs['dependencies'],kwargs['session'])
        
        else:
            return {'msg': "Token blocked"}
        
    return wrapper

#forgetpassword
def create_password_reset_token(email: str, expires_delta: timedelta = timedelta(hours=1)):
    to_encode = {"email": email, "exp": datetime.utcnow() + expires_delta}
    encoded_token = jwt.encode(to_encode, PASSWORD_RESET_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_token

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    email = Column(String, primary_key=True)
    reset_token = Column(String)
    reset_token_expiry = Column(DateTime)


email_address = "aayushi.fichadiya@gmail.com" # type Email
email_password = "rpyq nluu bmfx aafk"

def send_reset_email(email, token):
    msg = MIMEMultipart()
    msg['From'] = email_address  # Replace with your Gmail email
    msg['To'] = email
    msg['Subject'] = "Password Reset"
    body = f"Password Reset Token: {token}"
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(email_address, email_password)  # Replace with your Gmail email and password
    text = msg.as_string()
    server.sendmail(email_address, email, text)
    server.quit()


class ResetPassword(BaseModel):
    token: str
    new_password: str
    

@app.post("/forgot-password")
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    password_reset_token = create_password_reset_token(email)

    # Send the password reset token in an email to the user
    send_reset_email(email, password_reset_token)

    return {"message": "Password reset email sent"}

# Route to reset the password using the token
@app.post("/reset-password")
async def reset_password(reset_data: ResetPassword, db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(reset_data.token, PASSWORD_RESET_SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("email")

        # Verify that the email exists in your database
        user = db.query(User).filter(User.email == email).first()

        if user:
            # Check the token expiration
            if "exp" in payload and datetime.utcfromtimestamp(payload["exp"]) > datetime.utcnow():
                # Update the user's password
                hashed_password = get_hashed_password(reset_data.new_password)
                user.hashed_password = hashed_password
                db.commit()
                return {"message": "Password reset successfully"}

    except JWTError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password reset token is invalid")


