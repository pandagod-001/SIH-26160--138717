import sys
import os

# Ensure backend root is on sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database.models import init_db
from app.api.routes_health import router as health_router
from app.api.routes_pcaps import router as pcaps_router
from app.api.routes_analysis import router as analysis_router

app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="Defensive IPsec Protocol Analyzer and Encrypted Traffic Assessment Engine"
)

# CORS middleware for dashboards and frontend clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register API Routers
app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(pcaps_router, prefix=settings.API_V1_PREFIX)
app.include_router(analysis_router, prefix=settings.API_V1_PREFIX)

@app.on_event("startup")
def on_startup():
    init_db()

@app.get("/")
def root():
    return {
        "message": "IPsecTrace Defensive Traffic Analysis System",
        "docs_url": "/docs",
        "health_url": f"{settings.API_V1_PREFIX}/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("src.app.main:app", host=settings.SENTRY_HOST, port=settings.SENTRY_PORT, reload=settings.DEBUG)
