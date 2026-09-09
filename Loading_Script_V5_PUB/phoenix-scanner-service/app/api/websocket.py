"""WebSocket API for real-time log streaming"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict, Set
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.database import get_db
from app.services.job_manager import job_manager
from app.models.schemas import WebSocketMessage, JobStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manage WebSocket connections for job log streaming"""
    
    def __init__(self):
        # Map job_id -> set of WebSocket connections
        self.active_connections: Dict[str, Set[WebSocket]] = {}
        self.lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, job_id: str):
        """Connect a client to a job's log stream"""
        await websocket.accept()
        
        async with self.lock:
            if job_id not in self.active_connections:
                self.active_connections[job_id] = set()
            self.active_connections[job_id].add(websocket)
        
        logger.info(f"WebSocket connected for job {job_id} (total: {len(self.active_connections[job_id])})")
    
    async def disconnect(self, websocket: WebSocket, job_id: str):
        """Disconnect a client from a job's log stream"""
        async with self.lock:
            if job_id in self.active_connections:
                self.active_connections[job_id].discard(websocket)
                if not self.active_connections[job_id]:
                    del self.active_connections[job_id]
        
        logger.info(f"WebSocket disconnected for job {job_id}")
    
    async def send_message(self, message: dict, job_id: str):
        """Send message to all connected clients for a job"""
        async with self.lock:
            if job_id not in self.active_connections:
                return
            
            connections = list(self.active_connections[job_id])
        
        # Send to all connections (outside lock to avoid blocking)
        disconnected = []
        for connection in connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send message to client: {e}")
                disconnected.append(connection)
        
        # Clean up disconnected clients
        if disconnected:
            async with self.lock:
                if job_id in self.active_connections:
                    for conn in disconnected:
                        self.active_connections[job_id].discard(conn)
    
    async def broadcast_to_job(self, job_id: str, message_type: str, data: dict):
        """Broadcast a typed message to all clients watching a job"""
        message = WebSocketMessage(
            type=message_type,
            job_id=job_id,
            timestamp=datetime.utcnow(),
            data=data
        )
        await self.send_message(message.dict(), job_id)
    
    def get_connection_count(self, job_id: str) -> int:
        """Get number of active connections for a job"""
        return len(self.active_connections.get(job_id, set()))


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws/{job_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    job_id: str,
    db: Session = Depends(get_db)
):
    """
    WebSocket endpoint for real-time job log streaming.
    
    Connect to this endpoint to receive real-time updates about job processing:
    - Log messages
    - Progress updates
    - Status changes
    - Completion/error notifications
    
    Message format:
    ```json
    {
        "type": "log|status|progress|error|complete",
        "job_id": "job-123",
        "timestamp": "2025-11-12T10:30:00Z",
        "data": { ... }
    }
    ```
    """
    
    # Verify job exists
    job = job_manager.get_job(db, job_id)
    if not job:
        await websocket.close(code=1008, reason=f"Job {job_id} not found")
        return
    
    # Connect client
    await manager.connect(websocket, job_id)
    
    try:
        # Send welcome message
        await manager.broadcast_to_job(
            job_id,
            "connected",
            {
                "message": f"Connected to job {job_id}",
                "status": job.status,
                "progress": job.progress
            }
        )
        
        # Send current job status
        await manager.broadcast_to_job(
            job_id,
            "status",
            {
                "status": job.status,
                "progress": job.progress,
                "current_step": job.current_step,
                "filename": job.filename
            }
        )
        
        # Start log streaming task
        log_task = asyncio.create_task(stream_logs(websocket, job_id, db))
        
        # Keep connection alive and handle client messages
        try:
            while True:
                # Wait for client message (or timeout for heartbeat)
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(),
                        timeout=settings.WS_HEARTBEAT_INTERVAL
                    )
                    
                    # Handle client commands
                    try:
                        message = json.loads(data)
                        command = message.get('command')
                        
                        if command == 'ping':
                            await websocket.send_json({
                                'type': 'pong',
                                'timestamp': datetime.utcnow().isoformat()
                            })
                        elif command == 'get_status':
                            job = job_manager.get_job(db, job_id)
                            await manager.broadcast_to_job(
                                job_id,
                                "status",
                                {
                                    "status": job.status,
                                    "progress": job.progress,
                                    "current_step": job.current_step
                                }
                            )
                    except json.JSONDecodeError:
                        pass  # Ignore invalid JSON
                
                except asyncio.TimeoutError:
                    # Send heartbeat
                    await websocket.send_json({
                        'type': 'heartbeat',
                        'timestamp': datetime.utcnow().isoformat()
                    })
        
        except WebSocketDisconnect:
            logger.info(f"Client disconnected from job {job_id}")
        finally:
            log_task.cancel()
    
    finally:
        await manager.disconnect(websocket, job_id)


async def stream_logs(websocket: WebSocket, job_id: str, db: Session):
    """Stream log file contents in real-time"""
    log_file = job_manager.get_log_file_path(job_id)
    last_position = 0
    last_status = None
    
    while True:
        try:
            # Check if log file exists and read new content
            if log_file.exists():
                with open(log_file, 'r') as f:
                    f.seek(last_position)
                    new_lines = f.readlines()
                    last_position = f.tell()
                    
                    # Send new log lines
                    for line in new_lines:
                        line = line.strip()
                        if line:
                            # Parse log level from line
                            level = "INFO"
                            if " - ERROR - " in line:
                                level = "ERROR"
                            elif " - WARNING - " in line:
                                level = "WARNING"
                            elif " - DEBUG - " in line:
                                level = "DEBUG"
                            
                            await manager.broadcast_to_job(
                                job_id,
                                "log",
                                {
                                    "level": level,
                                    "message": line
                                }
                            )
            
            # Check job status and send updates
            job = job_manager.get_job(db, job_id)
            if job:
                current_status = (job.status, job.progress, job.current_step)
                
                if current_status != last_status:
                    await manager.broadcast_to_job(
                        job_id,
                        "progress",
                        {
                            "status": job.status,
                            "progress": job.progress,
                            "current_step": job.current_step
                        }
                    )
                    last_status = current_status
                
                # If job is complete or failed, send final message
                if job.status in [JobStatus.COMPLETED.value, JobStatus.FAILED.value, JobStatus.CANCELLED.value]:
                    message_type = "complete" if job.status == JobStatus.COMPLETED.value else "error"
                    
                    data = {
                        "status": job.status,
                        "progress": job.progress,
                    }
                    
                    if job.status == JobStatus.COMPLETED.value:
                        data.update({
                            "assets_imported": job.assets_imported,
                            "vulnerabilities_imported": job.vulnerabilities_imported,
                            "assessment_name": job.assessment_name
                        })
                    elif job.status == JobStatus.FAILED.value:
                        data.update({
                            "error_message": job.error_message
                        })
                    
                    await manager.broadcast_to_job(job_id, message_type, data)
                    
                    # Stop streaming after completion
                    await asyncio.sleep(5)  # Give clients time to receive final message
                    break
            
            # Wait before checking again
            await asyncio.sleep(0.5)
        
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error streaming logs for job {job_id}: {e}")
            await asyncio.sleep(1)


# Export connection manager for use in tasks
__all__ = ["router", "manager"]



