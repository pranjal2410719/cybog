from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
import uuid

from app.db.session import get_db
from app.db.models import DBUser
from app.models.auth import User, Role
from app.api.auth_routes import get_current_user
from app.api.routes import require_role
from app.services.auth_service import generate_uid
from app.services.passwords import hash_password
from pydantic import BaseModel, Field

user_router = APIRouter(prefix="/api/v1/users", tags=["users"])

class UserCreate(BaseModel):
    name: str
    role: Role
    # Initial password, set by Management at provisioning time.
    password: str = Field(..., min_length=12, description="Initial password (min 12 chars)")

@user_router.get("", response_model=List[User])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_role(current_user, {Role.MANAGEMENT})
    result = await db.execute(select(DBUser))
    users = result.scalars().all()
    return [
        User(
            id=u.id,
            uid=u.uid,
            name=u.name,
            role=u.role,
            active=u.active,
            created_at=u.created_at
        ) for u in users
    ]

@user_router.post("", response_model=User)
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    require_role(current_user, {Role.MANAGEMENT})

    # Role-prefixed UID with 128 bits of entropy (T1). The UID stays the
    # login identifier; the password is the credential.
    uid = generate_uid(user_in.role)
    user_id = str(uuid.uuid4())

    db_user = DBUser(
        id=user_id,
        uid=uid,
        name=user_in.name,
        role=user_in.role,
        password_hash=hash_password(user_in.password),
    )
    db.add(db_user)
    await db.commit()
    
    return User(
        id=db_user.id,
        uid=db_user.uid,
        name=db_user.name,
        role=db_user.role,
        active=db_user.active,
        created_at=db_user.created_at
    )
