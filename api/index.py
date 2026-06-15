import os
import sys
from pathlib import Path

# Add parent directory to path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from mangum import Mangum

from backend.cloud_ops.aws_ops import router as aws_router
from backend.cloud_ops.azure_ops import router as azure_router
from backend.cloud_ops.gcp_ops import router as gcp_router
from backend.database.database import engine, SessionLocal, Base
from backend.core.websocket_manager import manager
from backend.core.failover import monitor_primary_endpoint, global_state
import asyncio

# Load credentials
load_dotenv(override=True)

app = FastAPI(
    title="CloudGuard Multi-Cloud Sentinel",
    description="Autonomous cloud defense platform powered by AI.",
    version="1.0.0"
)

# Create database tables
Base.metadata.create_all(bind=engine)

# Enable CORS - ALLOW VERCEL FRONTEND
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://cloud-gaurd.vercel.app",
        "http://localhost:5173",  # Local dev
        "http://localhost:3000",  # Fallback local
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(aws_router, prefix="/api/aws", tags=["AWS"])
app.include_router(azure_router, prefix="/api/azure", tags=["Azure"])
app.include_router(gcp_router, prefix="/api/gcp", tags=["GCP"])

@app.get("/api/heartbeat")
async def provider_heartbeat():
    """
    Checks the heartbeat of connected cloud environments.
    """
    status = {
        "AWS": "Disconnected",
        "Azure": "Disconnected",
        "GCP": "Disconnected"
    }
    
    if os.getenv("AWS_ACCESS_KEY_ID"):
        status["AWS"] = "Connected (Idle)"
    if os.getenv("AZURE_CLIENT_ID"):
        status["Azure"] = "Connected (Idle)"
    if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        status["GCP"] = "Connected (Idle)"
        
    global_status = "online" if any("Connected" in v for v in status.values()) else "offline"
        
    return {
        "status": global_status,
        "providers": status
    }

# Export handler for Vercel
handler = Mangum(app, lifespan="off")
