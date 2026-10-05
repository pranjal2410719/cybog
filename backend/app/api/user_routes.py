from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List, Optional
import uuid
import secrets

from app.db.session import get_db
from app.db.models import DBUser
from app.models.auth import User, Role
from app.api.auth_routes import get_current_user
from app.api.routes import require_role
from pydantic import BaseModel

user_router = APIRouter(prefix="/api/v1/users", tags=["users"])

class UserCreate(BaseModel):
    name: str
    role: Role

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
    
    prefix = ""
    if user_in.role == Role.OPERATOR:
        prefix = "op_"
    elif user_in.role == Role.VALIDATOR:
        prefix = "val_"
    elif user_in.role == Role.MANAGEMENT:
        prefix = "mg_"
        
    random_id = secrets.token_hex(4)
    uid = f"{prefix}{random_id}"
    
    db_user = DBUser(
        uid=uid,
        name=user_in.name,
        role=user_in.role
    )
    db.add(db_user)
    await db.commit()
    await db.refresh(db_user)
    
    return User(
        uid=db_user.uid,
        name=db_user.name,
        role=db_user.role,
        active=db_user.active,
        created_at=db_user.created_at
    )
