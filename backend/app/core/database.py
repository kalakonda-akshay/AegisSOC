from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.core.config import settings
from app.core.logging import logger

db_url = settings.DATABASE_URL
if "sqlite+aiosqlite" in db_url:
    sync_url = db_url.replace("sqlite+aiosqlite", "sqlite")
elif "postgresql+asyncpg" in db_url:
    sync_url = db_url.replace("postgresql+asyncpg", "postgresql")
else:
    sync_url = db_url

connect_args = {"check_same_thread": False} if "sqlite" in sync_url else {}

engine = create_engine(
    sync_url,
    pool_pre_ping=True,
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False
)

Base = declarative_base()


def get_db() -> Generator:
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """Creates database tables and seeds default data on startup."""
    logger.info("Initializing database schema...")
    import app.models  # noqa
    Base.metadata.create_all(bind=engine)
    logger.info("Database schema initialized.")

    from app.utils.seed_data import seed_initial_data
    with SessionLocal() as session:
        seed_initial_data(session)
