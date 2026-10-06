from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from pathlib import Path
from app.config import settings

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = DATA_DIR / "cybog.db"

# Since it's a phase 1 MVP, we use sqlite
SQLALCHEMY_DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH}"

engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}, echo=False
)
async_session_maker = async_sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)

async def get_db():
    async with async_session_maker() as session:
        yield session
