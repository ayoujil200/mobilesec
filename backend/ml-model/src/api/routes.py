"""
FastAPI Routes for ML Model Service
"""

import asyncio
import os
import shutil
import sys

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Optional
import logging

from ..evaluation.paper_tables import generate_paper_tables
from ..model.predictor import predictor

logger = logging.getLogger(__name__)

router = APIRouter()
training_lock = asyncio.Lock()


def _sse_line(message: str, event: str = "log") -> str:
    safe_message = str(message).replace("\r", "")
    return "".join(f"data: {line}\n" for line in safe_message.split("\n")) + f"event: {event}\n\n"


async def _stream_process(command: List[str]):
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd="/app",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env={**os.environ, "PYTHONUNBUFFERED": "1"},
    )

    assert process.stdout is not None
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        yield _sse_line(line.decode("utf-8", errors="replace").rstrip())

    return_code = await process.wait()
    if return_code != 0:
        raise RuntimeError(f"Command failed with exit code {return_code}: {' '.join(command)}")


async def _run_training_pipeline(source: str):
    if training_lock.locked():
        yield _sse_line("Training is already running. Wait for it to finish before starting another run.", "error")
        return

    async with training_lock:
        try:
            os.makedirs("/app/data", exist_ok=True)
            os.makedirs("/app/models", exist_ok=True)

            yield _sse_line(f"Starting ML training pipeline. source={source}", "start")
            training_dataset = "data/security_scan_dataset.csv"

            if source == "mongodb":
                yield _sse_line("Extracting training rows from MongoDB...")
                async for line in _stream_process([sys.executable, "-m", "src.data.data_extractor"]):
                    yield line

                extracted_path = "/app/data/extracted_data.csv"
                dataset_path = "/app/data/security_scan_dataset.csv"
                if not os.path.exists(extracted_path):
                    raise RuntimeError("MongoDB extraction did not create /app/data/extracted_data.csv")

                shutil.copyfile(extracted_path, dataset_path)
                yield _sse_line("Copied extracted MongoDB dataset to /app/data/security_scan_dataset.csv")
                training_dataset = "data/extracted_data.csv"
            elif source == "extracted":
                extracted_path = "/app/data/extracted_data.csv"
                if not os.path.exists(extracted_path):
                    raise RuntimeError(
                        "Existing extracted dataset not found at /app/data/extracted_data.csv. "
                        "Run source=mongodb first to create it."
                    )
                yield _sse_line("Using existing extracted MongoDB dataset at /app/data/extracted_data.csv")
                training_dataset = "data/extracted_data.csv"
            elif source == "bootstrap":
                yield _sse_line("Creating balanced development dataset...")
                async for line in _stream_process([
                    sys.executable,
                    "-m",
                    "src.data.bootstrap_dataset",
                    "--output",
                    "data/security_scan_dataset.csv",
                ]):
                    yield line
            elif source == "controlled":
                labels_path = "/app/data/controlled_ground_truth_labels.csv"
                uploads_path = "/app/data/controlled_upload_results.json"
                if not os.path.exists(labels_path):
                    raise RuntimeError(
                        "Controlled labels file not found at /app/data/controlled_ground_truth_labels.csv. "
                        "Generate/upload the controlled APK dataset first."
                    )
                if not os.path.exists(uploads_path):
                    raise RuntimeError(
                        "Controlled upload results file not found at /app/data/controlled_upload_results.json. "
                        "Upload the controlled APKs first."
                    )

                yield _sse_line("Building trusted controlled training dataset from ground-truth labels...")
                async for line in _stream_process([
                    sys.executable,
                    "-m",
                    "src.data.build_controlled_dataset",
                    "--labels",
                    labels_path,
                    "--uploads",
                    uploads_path,
                    "--output",
                    "data/security_scan_dataset.csv",
                ]):
                    yield line
            else:
                raise RuntimeError(
                    "Invalid source. Use source=mongodb, source=extracted, source=bootstrap, or source=controlled."
                )

            yield _sse_line(f"Training LightGBM model from {training_dataset}...")
            async for line in _stream_process([sys.executable, "-m", "src.model.trainer", training_dataset]):
                yield line

            predictor.is_loaded = False
            predictor.load_model()
            yield _sse_line("Training finished and model reloaded successfully.", "done")
        except Exception as exc:
            logger.exception("Training pipeline failed")
            yield _sse_line(f"Training failed: {exc}", "error")


# Request/Response Models
class PredictionRequest(BaseModel):
    """Request model for manual predictions"""
    features: Dict[str, float] = Field(..., description="Feature dictionary")
    top_k: int = Field(3, ge=1, le=10, description="Number of suggestions to return")


class Suggestion(BaseModel):
    """Individual fix suggestion"""
    rank: int
    category: str
    confidence: float
    title: str
    description: str
    priority: str
    code_example: str


class VulnerabilitySummary(BaseModel):
    """Vulnerability counts summary"""
    crypto: int
    secrets: int
    network: int
    total: int
    severity_score: float


class PredictionResponse(BaseModel):
    """Response model for predictions"""
    scan_id: Optional[str] = None
    primary_fix: str
    confidence: float
    suggestions: List[Suggestion]
    vulnerability_summary: Optional[VulnerabilitySummary] = None


class ModelInfo(BaseModel):
    """Model metadata"""
    model_type: str
    num_classes: int
    classes: List[str]
    num_features: int
    features: List[str]
    model_path: str


# Routes
@router.post("/predict/{scan_id}", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
async def predict_for_scan(scan_id: str, top_k: int = 3):
    """
    Generate fix suggestions for a specific scan
    
    Args:
        scan_id: Scan ID from MongoDB
        top_k: Number of top suggestions to return (default: 3)
        
    Returns:
        Prediction response with fix suggestions
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        result = predictor.predict_from_scan_id(scan_id, top_k=top_k)
        return result
    
    except ValueError as e:
        logger.error(f"Scan not found: {scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID not found: {scan_id}"
        )
    except Exception as e:
        logger.error(f"Prediction error for scan {scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@router.post("/predict", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
async def predict_from_features(request: PredictionRequest):
    """
    Generate fix suggestions from raw features
    
    Args:
        request: Feature dictionary and top_k
        
    Returns:
        Prediction response with fix suggestions
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        result = predictor.predict_from_features(request.features, top_k=request.top_k)
        return result
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@router.get("/model/info", response_model=ModelInfo, status_code=status.HTTP_200_OK)
async def get_model_info():
    """
    Get model metadata
    
    Returns:
        Model information including classes and features
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        info = predictor.get_model_info()
        return info
    
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get model info: {str(e)}"
        )


@router.get("/train/stream", status_code=status.HTTP_200_OK)
async def train_model_stream(
    source: str = Query("mongodb", pattern="^(mongodb|extracted|bootstrap|controlled)$")
):
    """
    Stream model training logs.

    The endpoint only runs fixed internal training commands. It does not accept
    arbitrary shell input from the browser.
    """
    return StreamingResponse(
        _run_training_pipeline(source),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/paper/tables", status_code=status.HTTP_200_OK)
async def get_paper_tables():
    """
    Generate paper-ready table values from current MobileSec artifacts.

    Values are computed from MongoDB scan results, the training CSV, and
    training_metrics.json. Metrics requiring ground truth or external tools are
    reported as null/N/A with warnings.
    """
    try:
        return generate_paper_tables()
    except Exception as e:
        logger.error(f"Failed to generate paper tables: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate paper tables: {str(e)}"
        )




@router.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    """
    Health check endpoint
    
    Returns:
        Service health status
    """
    is_ready = predictor.is_loaded
    
    return {
        "status": "healthy" if is_ready else "initializing",
        "model_loaded": is_ready,
        "service": "ml-model"
    }


# New Endpoint for Vulnerability Prioritization
class VulnerabilityInput(BaseModel):
    """Single vulnerability for prioritization"""
    id: str
    title: str
    severity: str
    file: Optional[str] = None
    line: Optional[int] = None
    description: Optional[str] = None


class PrioritizationRequest(BaseModel):
    """Request model for bulk prioritization"""
    scan_id: str
    vulnerabilities: List[VulnerabilityInput] = Field(..., description="List of vulnerabilities to prioritize")


class PrioritizedVulnerability(BaseModel):
    """Prioritized vulnerability with LightGBM score"""
    vulnerability_id: str
    vulnerability_title: str
    severity: str
    file: Optional[str]
    lightgbm_category: str
    confidence: float
    priority_rank: int


class PrioritizationResponse(BaseModel):
    """Response model for prioritization"""
    scan_id: str
    total_vulnerabilities: int
    prioritized: List[PrioritizedVulnerability]


@router.post("/prioritize", response_model=PrioritizationResponse, status_code=status.HTTP_200_OK)
async def prioritize_vulnerabilities(request: PrioritizationRequest):
    """
    Prioritize vulnerabilities using LightGBM model
    
    This endpoint accepts a list of vulnerabilities and returns them sorted
    by LightGBM confidence score (highest first). This allows downstream
    services (like FixSuggest) to generate AI suggestions for the most
    critical vulnerabilities first.
    
    Args:
        request: Scan ID and list of vulnerabilities
        
    Returns:
        Prioritized vulnerabilities with confidence scores
    """
    try:
        if not predictor.is_loaded:
            predictor.load_model()
        
        logger.info(f"Prioritizing {len(request.vulnerabilities)} vulnerabilities for scan {request.scan_id}")
        
        # Get LightGBM prediction for the scan
        scan_prediction = predictor.predict_from_scan_id(request.scan_id, top_k=5)
        
        # Map vulnerabilities to their priorities
        # For now, assign the same LightGBM scores to all vulns (since LightGBM predicts fix categories, not individual vulns)
        # In a more sophisticated version, we could analyze each vuln individually
        primary_category = scan_prediction['primary_fix']
        primary_confidence = scan_prediction['confidence']
        
        prioritized = []
        for idx, vuln in enumerate(request.vulnerabilities):
            # Assign priority based on severity if available
            severity_weights = {
                'CRITICAL': 1.0,
                'HIGH': 0.8,
                'MEDIUM': 0.6,
                'LOW': 0.4,
                'INFO': 0.2
            }
            
            severity_weight = severity_weights.get(vuln.severity.upper(), 0.5)
            adjusted_confidence = primary_confidence * severity_weight
            
            prioritized.append({
                'vulnerability_id': vuln.id,
                'vulnerability_title': vuln.title,
                'severity': vuln.severity,
                'file': vuln.file,
                'lightgbm_category': primary_category,
                'confidence': round(adjusted_confidence, 4),
                'priority_rank': idx + 1  # Will be re-ranked after sorting
            })
        
        # Sort by confidence (descending)
        prioritized.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Update priority ranks
        for idx, item in enumerate(prioritized):
            item['priority_rank'] = idx + 1
        
        logger.info(f"Prioritization complete. Top vulnerability: {prioritized[0]['vulnerability_title'] if prioritized else 'None'}")
        
        return {
            'scan_id': request.scan_id,
            'total_vulnerabilities': len(prioritized),
            'prioritized': prioritized
        }
    
    except ValueError as e:
        logger.error(f"Scan not found: {request.scan_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan ID not found: {request.scan_id}"
        )
    except Exception as e:
        logger.error(f"Prioritization error for scan {request.scan_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prioritization failed: {str(e)}"
        )
