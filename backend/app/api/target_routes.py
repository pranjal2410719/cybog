from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
import uuid
from typing import List

from app.db.session import get_db
from app.db.models import DBTarget, DBUser
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
    target_id = str(uuid.uuid4())
    target = DBTarget(
        id=target_id,
        name=target_in.name,
        domain=target_in.domain,
        description=target_in.description,
        owner_id=user.id
    )
    db.add(target)
    await db.commit()
    
    return TargetResponse(
        id=target.id,
        name=target.name,
        domain=target.domain,
        description=target.description,
        owner_uid=user.uid,
        created_at=target.created_at.isoformat()
    )

@target_router.get("", response_model=List[TargetResponse])
async def list_targets(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    if user.role == Role.MANAGEMENT:
        stmt = select(DBTarget, DBUser).join(DBUser, DBTarget.owner_id == DBUser.id)
        result = await db.execute(stmt)
        rows = result.all()
        
        return [
            TargetResponse(
                id=t.id,
                name=t.name,
                domain=t.domain,
                description=t.description,
                owner_uid=u.uid,
                created_at=t.created_at.isoformat()
            )
            for t, u in rows
        ]
    else:
        stmt = select(DBTarget).where(DBTarget.owner_id == user.id)
        result = await db.execute(stmt)
        targets = result.scalars().all()
        
        return [
            TargetResponse(
                id=t.id,
                name=t.name,
                domain=t.domain,
                description=t.description,
                owner_uid=user.uid,
                created_at=t.created_at.isoformat()
            )
            for t in targets
        ]
