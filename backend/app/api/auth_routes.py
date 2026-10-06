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
from app.models.auth import AuditEvent, Role, User
from app.services.auth_service import audit_log
from app.services.passwords import verify_password

auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
security = HTTPBearer(auto_error=False)

class LoginRequest(BaseModel):
    uid: str
    password: str
    # Optional role selected via the login card. When provided, the
    # backend verifies it against the DB user record — the card is a
    # UX affordance, never authority. Mismatch → 401 with a specific
    # message (the UID prefix is a consistency hint only).
    selected_role: Optional[str] = None

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

    # Generic failure for unknown/inactive users, unset passwords, and
    # wrong passwords alike: no credential oracle beyond "login failed".
    if (
        not db_user
        or not db_user.active
        or not verify_password(request.password, db_user.password_hash)
    ):
        audit_log.append(AuditEvent(
            actor_uid=request.uid,
            action="auth.login_failed",
            resource="auth:login",
        ))
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if request.selected_role and request.selected_role != db_user.role.value:
        audit_log.append(AuditEvent(
            actor_uid=request.uid,
            action="auth.login_failed",
            resource="auth:login",
            detail=f"role mismatch: selected {request.selected_role}",
        ))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This UID belongs to another role.",
        )

    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(days=1)

    user = User(
        id=db_user.id,
        uid=db_user.uid,
        name=db_user.name,
        role=db_user.role,
        active=db_user.active,
        created_at=db_user.created_at
    )

    new_session = DBSession(
        token=token,
        user_id=db_user.id,
        expires_at=expires_at
    )
    db.add(new_session)
    await db.commit()

    audit_log.append(AuditEvent(
        actor_uid=db_user.uid,
        actor_user_id=db_user.id,
        action="auth.login",
        resource="auth:login",
    ))

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
            result = await db.execute(select(DBUser).where(DBUser.id == session.user_id))
            db_user = result.scalar_one_or_none()
            await db.delete(session)
            await db.commit()
            audit_log.append(AuditEvent(
                actor_uid=db_user.uid if db_user else "unknown",
                actor_user_id=db_user.id if db_user else None,
                action="auth.logout",
                resource="auth:logout",
            ))
    return {"status": "success"}
