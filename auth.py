from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
import os
from dotenv import load_dotenv

load_dotenv()

secret = os.getenv("SECRET_KEY")
algorithm = os.getenv("ALGORITHM")
token_expiry = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

oauth2_schema = OAuth2PasswordBearer(tokenUrl="login")


def create_token(data: dict):
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + timedelta(minutes=token_expiry)

    to_encode.update({"exp":expire})

    return jwt.encode(to_encode, secret, algorithm=algorithm)

def verify_token(token:str = Depends(oauth2_schema)):
    try:
        payload = jwt.decode(token, secret, algorithms=algorithm)
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")