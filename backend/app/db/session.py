from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from app.config import settings

# Since it's a phase 1 MVP, we use sqlite
SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./cybog.db"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, echo=False
)
async_session_maker = async_sessionmaker(autocommit=False, autoflush=False, bind=engine)

async def get_db():
    async with async_session_maker() as session:
        yield session
