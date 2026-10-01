import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from app.database import Base

class BackupRecord(Base):
    __tablename__ = "backup_records"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    version = Column(String, default="v1")
    sha256_digest = Column(String(64), nullable=False)
    encrypted_path = Column(String, nullable=False)
    retention_expiry = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    action_type = Column(String, nullable=False)
    status = Column(String, nullable=False)
    details = Column(String, nullable=False)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="operator")
    is_active = Column(Boolean, default=True)