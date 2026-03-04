from sqlalchemy import Column, String, Integer, DateTime
from datetime import datetime
import uuid
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    current_epoch = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

