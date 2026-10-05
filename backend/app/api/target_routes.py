from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List

from app.db.session import get_db
from app.db.models import DBTarget
from app.models.auth import User, Role
from app.models.api import TargetCreate, TargetResponse
from app.api.auth_routes import get_current_user

target_router = APIRouter(prefix="/api/v1/targets", tags=["targets"])

@target_router.post("", response_model=TargetResponse)
async def create_target(
    target_in: TargetCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    target = DBTarget(
        name=target_in.name,
        domain=target_in.domain,
        description=target_in.description,
        owner_uid=user.uid  # Wait, owner_uid is foreign key to users.id or users.uid? Let's check DBUser
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    
    return TargetResponse(
        id=target.id,
        name=target.name,
        domain=target.domain,
        description=target.description,
        owner_uid=target.owner_uid,
        created_at=target.created_at.isoformat()
    )

@target_router.get("", response_model=List[TargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if user.role == Role.MANAGEMENT:
        stmt = select(DBTarget)
    else:
        # Get user id based on uid?
        stmt = select(DBTarget).where(DBTarget.owner_uid == user.uid)
        
    result = await db.execute(stmt)
    targets = result.scalars().all()
    
    return [
        TargetResponse(
            id=t.id,
            name=t.name,
            domain=t.domain,
            description=t.description,
            owner_uid=t.owner_uid,
            created_at=t.created_at.isoformat()
        )
        for t in targets
    ]
