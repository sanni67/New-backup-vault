import os
import datetime
from fastapi import FastAPI, Depends, HTTPException, status, Form, UploadFile, File
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db, engine, Base
from app.models import BackupRecord, AuditLog, User
from app.crypto import encrypt_file, decrypt_file, calculate_sha256
from app.auth import (
    authenticate_user, 
    create_access_token, 
    get_current_user, 
    get_password_hash
)

app = FastAPI(title="Ransomware-Resilient Backup Vault", version="0.1.0")

# Auto-create all tables on startup
Base.metadata.create_all(bind=engine)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.on_event("startup")
def startup_db_seed():
    db = next(get_db())
    if not db.query(User).filter(User.username == "admin").first():
        admin_user = User(
            username="admin",
            hashed_password=get_password_hash("admin123"),
            role="operator"
        )
        db.add(admin_user)
        db.commit()

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

# Auth Token Endpoint
@app.post("/api/v1/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), 
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {"access_token": access_token, "token_type": "bearer"}

# Explicit GET for Listing Backups
@app.get("/api/v1/backups")
def get_backups(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    backups = db.query(BackupRecord).all()
    result = []
    for b in backups:
        # Extract digest from whatever field exists on the database model
        digest = (
            getattr(b, "sha256_digest", None)
            or getattr(b, "file_hash", None)
            or getattr(b, "hash", None)
            or getattr(b, "digest", None)
        )
        result.append({
            "id": b.id,
            "filename": b.filename,
            "version": getattr(b, "version", 1),
            "sha256_digest": digest,
            "retention_expiry": str(b.retention_expiry) if b.retention_expiry else None,
        })
    return result

# Explicit POST for Uploading Backups
@app.post("/api/v1/backups")
async def create_backup(
    file: UploadFile = File(...), 
    retention_days: int = Form(...), 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    content = await file.read()
    digest = calculate_sha256(content)
    encrypted_data = encrypt_file(content)
    
    os.makedirs("vault_storage", exist_ok=True)
    filename_str = file.filename if file.filename else "file"
    timestamp_prefix = int(datetime.datetime.utcnow().timestamp())
    storage_filename = f"{timestamp_prefix}_{filename_str}.enc"
    encrypted_path = os.path.join("vault_storage", storage_filename)
    
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)
        
    now = datetime.datetime.utcnow()
    retention_until = now + datetime.timedelta(days=retention_days)
    
    record = BackupRecord(
        filename=filename_str,
        version=1,
        sha256_digest=digest,
        encrypted_path=encrypted_path,
        retention_expiry=retention_until,
        created_at=now
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    
    log = AuditLog(
        timestamp=now,
        action_type="BACKUP_CREATED",
        status="SUCCESS",
        details=f"File: {filename_str}, Hash: {digest[:8]}..., Lock until: {retention_until}"
    )
    db.add(log)
    db.commit()
    
    return {"status": "SUCCESS", "record_id": record.id}

# Explicit DELETE for Purging Backups
@app.delete("/api/v1/backups/{record_id}")
def delete_backup(
    record_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(BackupRecord).filter(BackupRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
        
    now = datetime.datetime.utcnow()
    if now < record.retention_expiry:
        log = AuditLog(
            timestamp=now,
            action_type="DELETE_ATTEMPT",
            status="DENIED",
            details=f"Blocked attempt to purge locked backup ID {record_id}"
        )
        db.add(log)
        db.commit()
        raise HTTPException(
            status_code=403, 
            detail="Immutable Retention Lock Active. File cannot be purged until lock expires."
        )
        
    if os.path.exists(record.encrypted_path):
        os.remove(record.encrypted_path)
        
    db.delete(record)
    
    log = AuditLog(
        timestamp=now,
        action_type="DELETE_PERMITTED",
        status="SUCCESS",
        details=f"Purged backup ID {record_id} after lock expiration"
    )
    db.add(log)
    db.commit()
    
    return {"status": "PURGED"}

# Explicit POST for Restoring Backups
@app.post("/api/v1/restore/{record_id}")
def restore_backup(
    record_id: int, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(BackupRecord).filter(BackupRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
        
    try:
        with open(record.encrypted_path, "rb") as f:
            cipher_data = f.read()
        decrypted_data = decrypt_file(cipher_data)
        computed_hash = calculate_sha256(decrypted_data)
        
        if computed_hash != record.sha256_digest:
            raise ValueError("Digest mismatch")
            
        now = datetime.datetime.utcnow()
        log = AuditLog(
            timestamp=now,
            action_type="RESTORE_VERIFY",
            status="SUCCESS",
            details=f"Record ID {record_id} restored and hash verified."
        )
        db.add(log)
        db.commit()
        
        return {"filename": record.filename, "hash": computed_hash}
    except Exception as e:
        now = datetime.datetime.utcnow()
        log = AuditLog(
            timestamp=now,
            action_type="RESTORE_VERIFY",
            status="CORRUPTED",
            details=f"Decryption or integrity check failed for Record ID {record_id}"
        )
        db.add(log)
        db.commit()
        raise HTTPException(status_code=500, detail="Decryption Failure: Object modified or corrupted.")

# Explicit GET for Audit Logs
# Download Endpoint
@app.get("/api/v1/download/{record_id}")
def download_backup(
    record_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    record = db.query(BackupRecord).filter(BackupRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
        
    if not os.path.exists(record.encrypted_path):
        raise HTTPException(status_code=404, detail="Encrypted backup file missing from storage.")
        
    try:
        with open(record.encrypted_path, "rb") as f:
            cipher_data = f.read()
            
        decrypted_data = decrypt_file(cipher_data)
        
        log = AuditLog(
            timestamp=datetime.datetime.utcnow(),
            action_type="FILE_DOWNLOAD",
            status="SUCCESS",
            details=f"Downloaded and decrypted record ID {record_id} ({record.filename})"
        )
        db.add(log)
        db.commit()
        
        return Response(
            content=decrypted_data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{record.filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail="Decryption failure while preparing file download.")
@app.get("/api/v1/logs")
def get_audit_logs(
    
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).all()
    result = []
    for l in logs:
        result.append({
            "id": l.id,
            "timestamp": l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else "",
            "action": l.action_type,
            "status": l.status,
            "details": l.details
        })
    return result