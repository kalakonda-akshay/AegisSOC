import os
import shutil
import tempfile
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.dashboard import SecurityEventFeedItem
from app.schemas.telemetry import (
    EngineStatusResponse,
    InterfaceInfo,
    NetworkThroughputResponse,
    NetworkTopologyResponse,
    PCAPAnalysisResponse,
    SimulateRequest,
    StartCaptureRequest,
    SystemHealthItem
)
from app.services.monitoring_service import MonitoringService

router = APIRouter(prefix="/monitoring", tags=["Monitoring"])


@router.get("/traffic", response_model=NetworkThroughputResponse)
def get_traffic_telemetry(db: Session = Depends(get_db)):
    """Returns network throughput history (tIn, tOut) and current Mbps readings."""
    service = MonitoringService(db)
    return service.get_traffic_throughput()


@router.get("/topology", response_model=NetworkTopologyResponse)
def get_network_topology(db: Session = Depends(get_db)):
    """Returns the operational network node topology and compromise states for the live perimeter map."""
    service = MonitoringService(db)
    return service.get_topology()


@router.get("/health", response_model=List[SystemHealthItem])
def get_subsystems_health(db: Session = Depends(get_db)):
    """Returns diagnostic health metrics and latencies for internal SOC engines and connections."""
    service = MonitoringService(db)
    return service.get_health_status()


@router.get("/status", response_model=EngineStatusResponse)
@router.get("/engine/status", response_model=EngineStatusResponse)
def get_monitoring_engine_status(db: Session = Depends(get_db)):
    """Returns the real-time operational status, statistics, and health of the Scapy network engine."""
    service = MonitoringService(db)
    return service.get_engine_status()


@router.get("/events", response_model=List[SecurityEventFeedItem])
def get_monitoring_events_feed(
    limit: int = 25,
    db: Session = Depends(get_db)
):
    """Returns chronological security events for the live monitoring feed."""
    from app.services.dashboard_service import DashboardService
    service = DashboardService(db)
    return service.get_events(limit=limit)


@router.get("/interfaces", response_model=List[InterfaceInfo])
def list_network_interfaces(db: Session = Depends(get_db)):
    """Lists authorized system network interfaces available for live packet capture."""
    service = MonitoringService(db)
    return service.get_interfaces()


@router.post("/start")
def start_network_monitoring(req: StartCaptureRequest, db: Session = Depends(get_db)):
    """Safely starts authorized live network interface packet capture."""
    service = MonitoringService(db)
    try:
        return service.start_monitoring(req)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start live network capture: {str(e)}"
        )


@router.post("/stop")
def stop_network_monitoring(db: Session = Depends(get_db)):
    """Safely stops any active network interface capture or traffic simulation."""
    service = MonitoringService(db)
    return service.stop_monitoring()


@router.post("/simulate")
def start_traffic_simulation(req: SimulateRequest, db: Session = Depends(get_db)):
    """Starts safe, controlled synthetic traffic streaming for SOC pipeline validation."""
    service = MonitoringService(db)
    return service.start_simulation(req)


@router.post("/pcap/sample")
def generate_sample_pcap(db: Session = Depends(get_db)):
    """Generates a synthetic PCAP capture file containing controlled benign & anomaly packets."""
    service = MonitoringService(db)
    try:
        filepath = service.create_sample_pcap()
        return {
            "success": True,
            "filepath": filepath,
            "traffic_type": "simulated",
            "message": "Sample PCAP generated successfully."
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate sample PCAP: {str(e)}"
        )


MAX_PCAP_BYTES = 50 * 1024 * 1024  # 50 MB max limit
ALLOWED_PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
PCAP_MAGIC_HEADERS = [
    b"\xd4\xc3\xb2\xa1",  # Standard pcap (little endian)
    b"\xa1\xb2\xc3\xd4",  # Standard pcap (big endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond pcap (little endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond pcap (big endian)
    b"\x0a\x0d\x0d\x0a",  # PCAP-NG section header block
]


@router.post("/pcap/analyze", response_model=PCAPAnalysisResponse)
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """
    Ingests and analyzes an uploaded PCAP capture file offline.
    Enforces strict file type validation, magic byte checking, and size limits.
    """
    service = MonitoringService(db)
    tmp_path = None
    try:
        # 1. Validate filename and extension
        raw_name = os.path.basename(file.filename or "capture.pcap")
        suffix = os.path.splitext(raw_name)[1].lower()
        if suffix not in ALLOWED_PCAP_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file extension '{suffix}'. Allowed formats: {', '.join(sorted(ALLOWED_PCAP_EXTENSIONS))}"
            )

        # 2. Check magic header bytes
        header = await file.read(4)
        await file.seek(0)
        if len(header) < 4 or not any(header.startswith(magic) for magic in PCAP_MAGIC_HEADERS):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid PCAP file header. Uploaded file is not a valid PCAP or PCAPNG packet capture."
            )

        # 3. Stream to temporary file with bounded size check (50 MB)
        total_bytes = 0
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = tmp.name
            while chunk := await file.read(64 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_PCAP_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="Uploaded PCAP exceeds maximum allowed size of 50 MB."
                    )
                tmp.write(chunk)

        result = service.analyze_pcap_file(tmp_path, traffic_type="simulated")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error parsing PCAP file: {str(e)}"
        )
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
