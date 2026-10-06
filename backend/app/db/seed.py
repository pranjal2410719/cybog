import asyncio
from app.db.session import async_session_maker
from app.db.models import DBUser
from app.models.auth import Role

async def seed():
    async with async_session_maker() as session:
        seeds = [
            ("op_0001", "Ada Lovelace", Role.OPERATOR),
            ("val_0024", "Grace Hopper", Role.VALIDATOR),
            ("mg_0099", "Katherine Johnson", Role.MANAGEMENT),
            ("USR-0001", "Ada Lovelace", Role.OPERATOR),
            ("USR-0024", "Grace Hopper", Role.VALIDATOR),
            ("USR-0099", "Katherine Johnson", Role.MANAGEMENT),
        ]
        
        for uid, name, role in seeds:
            # Check if user exists
            from sqlalchemy.future import select
            result = await session.execute(select(DBUser).where(DBUser.uid == uid))
            if not result.scalar_one_or_none():
                user = DBUser(uid=uid, name=name, role=role)
                session.add(user)
        
        await session.commit()
        print("Database seeded successfully.")

if __name__ == "__main__":
    asyncio.run(seed())
