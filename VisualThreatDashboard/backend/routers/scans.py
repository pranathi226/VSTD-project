"""
Scans router — POST /scan, GET /scans, GET /scans/{id}
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import ScanResult, User
from ..schemas import ScanRequest, ScanResultOut
from ..auth import get_current_user
from ..services.scanner import dispatch_scan, sanitize_target

router = APIRouter(prefix="/scans", tags=["Scans"])


# ── Background task ──

async def _execute_scan(scan_id: int, target: str, tool: str, db_url: str):
    """Run the scan in the background and update the DB row."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(db_url, pool_pre_ping=True)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if not scan:
            return

        scan.status = "running"
        db.commit()

        result = await dispatch_scan(tool, target)

        scan.raw_output = result["raw_output"]
        scan.parsed_result = result["parsed_result"]
        scan.threat_score = result["threat_score"]
        scan.risk_level = result["risk_level"]
        scan.status = "completed"
        db.commit()

    except Exception as e:
        scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.raw_output = f"Error: {str(e)}"
            db.commit()
    finally:
        db.close()


# ── Endpoints ──

@router.post("/scan", response_model=ScanResultOut, status_code=201)
async def create_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start an async scan. Returns immediately with status='pending'."""
    # Validate target
    try:
        target = sanitize_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Create DB record
    scan = ScanResult(
        target=target,
        selected_tool=req.selected_tool,
        user_id=current_user.id,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Dispatch background scan
    from ..database import DATABASE_URL
    background_tasks.add_task(_execute_scan, scan.id, target, req.selected_tool, DATABASE_URL)

    return scan


@router.get("", response_model=List[ScanResultOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Return scan history for the authenticated user (newest first)."""
    return (
        db.query(ScanResult)
        .filter(ScanResult.user_id == current_user.id)
        .order_by(ScanResult.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


@router.get("/{scan_id}", response_model=ScanResultOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get a single scan result by ID."""
    scan = (
        db.query(ScanResult)
        .filter(ScanResult.id == scan_id, ScanResult.user_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan
