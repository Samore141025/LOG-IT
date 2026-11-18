from __future__ import annotations

import logging
import random
import time
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from core.config import DatabaseConfig
from core.db.models import Base

logger = logging.getLogger(__name__)


def get_engine(db_config: DatabaseConfig) -> Engine:
    is_sqlite = db_config.url.startswith("sqlite")
    connect_args = {"check_same_thread": False} if is_sqlite else {}

    if is_sqlite:
        return create_engine(
            db_config.url,
            connect_args=connect_args,
            echo=False,
        )
    return create_engine(
        db_config.url,
        pool_size=db_config.pool_size,
        max_overflow=db_config.max_overflow,
        pool_timeout=db_config.pool_timeout,
        pool_recycle=db_config.pool_recycle,
        echo=False,
    )


class DatabaseManager:
    def __init__(self, db_config: DatabaseConfig):
        self.config = db_config
        self.engine = get_engine(db_config)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def init_tables(self) -> None:
        Base.metadata.create_all(bind=self.engine)

    def check_connection_with_retry(
        self,
        max_retries: int = 2,
        base_delay: float = 0.1,
        fallback_to_sqlite: bool = True,
    ) -> bool:
        if self.config.url.startswith("sqlite"):
            return True

        # Fast socket pre-check for local PostgreSQL to avoid long connection timeouts
        if "localhost" in self.config.url or "127.0.0.1" in self.config.url:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.15)
            result = sock.connect_ex(("127.0.0.1", 5432))
            sock.close()
            if result != 0:
                if fallback_to_sqlite:
                    logger.info("Local PostgreSQL not detected on port 5432. Autonomous fail-safe: using local database.")
                    from pathlib import Path
                    db_name = "shugo_cyber.db" if Path("shugo_cyber.db").is_file() and not Path("logit_cyber.db").is_file() else "logit_cyber.db"
                    self.config.url = f"sqlite:///{db_name}"
                    self.engine = get_engine(self.config)
                    self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
                    return True

        for attempt in range(1, max_retries + 1):
            try:
                with self.engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                return True
            except OperationalError as e:
                if attempt == max_retries:
                    if fallback_to_sqlite:
                        logger.info("PostgreSQL unavailable. Autonomous fail-safe: using local database.")
                        from pathlib import Path
                        db_name = "shugo_cyber.db" if Path("shugo_cyber.db").is_file() and not Path("logit_cyber.db").is_file() else "logit_cyber.db"
                        self.config.url = f"sqlite:///{db_name}"
                        self.engine = get_engine(self.config)
                        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
                        return True
                    raise

                jitter = random.uniform(0.05, 0.15)
                delay = (base_delay * (2 ** (attempt - 1))) + jitter
                time.sleep(delay)
        return False

    @contextmanager
    def session(self) -> Generator[Session, None, None]:
        session: Session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
