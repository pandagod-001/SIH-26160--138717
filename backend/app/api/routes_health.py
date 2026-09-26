from fastapi import APIRouter

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "IPsecTrace Defensive Traffic Analysis Engine",
        "version": "1.0.0",
        "cryptographic_observability": "HEADER_ONLY_NO_DECRYPTION"
    }
