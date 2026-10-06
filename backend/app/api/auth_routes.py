from typing import Any, Dict, Optional
import secrets
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from pydantic import BaseModel

from app.db.session import get_db
from app.db.models import DBUser, DBSession
from app.models.auth import Role, User

auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

class LoginRequest(BaseModel):
    uid: str

class LoginResponse(BaseModel):
    token: str
    user: User

class UserResponse(BaseModel):
    user: User

async def get_optional_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    if not credentials:
        return None
    
    token = credentials.credentials
    result = await db.execute(select(DBSession).where(DBSession.token == token))
    session = result.scalar_one_or_none()
    
    if not session or session.expires_at < datetime.utcnow():
        return None
    
    result = await db.execute(select(DBUser).where(DBUser.id == session.user_id))
    db_user = result.scalar_one_or_none()
    if not db_user or not db_user.active:
        return None
        
    return User(
        id=db_user.id,
        uid=db_user.uid,
        name=db_user.name,
        role=db_user.role,
        active=db_user.active,
        created_at=db_user.created_at
    )

async def get_current_user(
    user: Optional[User] = Depends(get_optional_current_user)
) -> User:
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user


@auth_router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(DBUser).where(DBUser.uid == request.uid))
    db_user = result.scalar_one_or_none()
    
    if not db_user or not db_user.active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=1)
    
    new_session = DBSession(
        token=token,
        user_id=db_user.id,
        expires_at=expires_at
    )
    db.add(new_session)
    await db.commit()
    
    user = User(
        id=db_user.id,
        uid=db_user.uid,
        name=db_user.name,
        role=db_user.role,
        active=db_user.active,
        created_at=db_user.created_at
    )
    return LoginResponse(token=token, user=user)


@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(user=current_user)


@auth_router.post("/logout")
async def logout(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
):
    if credentials:
        token = credentials.credentials
        result = await db.execute(select(DBSession).where(DBSession.token == token))
        session = result.scalar_one_or_none()
        if session:
            await db.delete(session)
            await db.commit()
    return {"status": "success"}
