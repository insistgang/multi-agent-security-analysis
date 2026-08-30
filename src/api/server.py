#!/usr/bin/env python3
"""
API
RESTful API
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, UploadFile, File, Request, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
import argparse
import asyncio
import time
import uuid
from datetime import datetime
from pathlib import Path
from loguru import logger
import json

# 
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agents.multi_agent_system import MultiAgentSystem
from src.parsers.log_parser import AlertLogParser
from src.rag.rag_enhanced_analyzer import RAGEnhancedAnalyzer
from src.utils.path_guard import resolve_log_path, UnsafePathError, DEFAULT_DATA_DIR

# 
logger.add("logs/api_server.log", rotation="10 MB", level="INFO")

# JSONdatetime
class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def safe_json_dumps(obj):
    """JSONdatetime"""
    try:
        return json.dumps(obj, cls=DateTimeEncoder, ensure_ascii=False)
    except Exception as e:
        logger.error(f"JSON: {e}")
        # 
        try:
            return json.dumps(str(obj), ensure_ascii=False)
        except:
            return "{}"

# FastAPI
app = FastAPI(
    title="Network Threat Analysis System",
    description="API for network security threat analysis",
    version="1.0.0"
)

API_KEY = os.getenv("API_KEY", "").strip()
_cors_origins = [item.strip() for item in os.getenv(
    "CORS_ORIGINS",
    "http://localhost:7777,http://127.0.0.1:7777,http://localhost:8886,http://127.0.0.1:8886",
).split(",") if item.strip()]
if _cors_origins == ["*"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


async def require_api_key(
    request: Request,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
):
    """If API_KEY is set, require it on /api/v1/* except liveness."""
    if not API_KEY:
        return
    provided = x_api_key
    if not provided and authorization and authorization.lower().startswith("bearer "):
        provided = authorization.split(" ", 1)[1].strip()
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

# 
multi_agent_system = None
rag_analyzer = None
log_parser = None

# /
class AlertAnalysisRequest(BaseModel):
    """"""
    alert_data: Dict[str, Any] = Field(..., description="")
    enable_rag_enhancement: bool = Field(True, description="RAG")
    analysis_options: Dict[str, Any] = Field(default_factory=dict, description="")

class BatchAnalysisRequest(BaseModel):
    """"""
    alert_list: List[Dict[str, Any]] = Field(..., description="")
    enable_rag_enhancement: bool = Field(True, description="RAG")
    max_workers: int = Field(4, description="")

class AnalysisResponse(BaseModel):
    """"""
    success: bool
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    processing_time: float
    request_id: str
    timestamp: datetime

class SystemStatusResponse(BaseModel):
    """"""
    system_status: Dict[str, Any]
    agent_status: Dict[str, Any]
    rag_status: Dict[str, Any]
    performance_metrics: Dict[str, Any]

# 
async def initialize_system():
    """"""
    global multi_agent_system, rag_analyzer, log_parser

    try:
        logger.info("...")

        # 
        multi_agent_system = MultiAgentSystem()
        if not multi_agent_system.initialize():
            raise RuntimeError("")

        # RAG
        rag_analyzer = RAGEnhancedAnalyzer()
        if not rag_analyzer.initialize():
            raise RuntimeError("RAG")

        # 
        log_parser = AlertLogParser()

        logger.info("System initialized")
        return True

    except Exception as e:
        logger.warning(f"System initialization error: {e}")
        if multi_agent_system is None or not getattr(multi_agent_system, "is_initialized", False):
            logger.error("Multi-agent system failed to start")
            return False
        logger.warning("Continuing without RAG enhancement")
        rag_analyzer = None
        if log_parser is None:
            log_parser = AlertLogParser()
        return True

# 
@app.on_event("startup")
async def startup_event():
    """"""
    success = await initialize_system()
    if not success:
        logger.error("")
        raise RuntimeError("")

    logger.info("API")

# 
@app.on_event("shutdown")
async def shutdown_event():
    """"""
    logger.info("...")

    if multi_agent_system:
        multi_agent_system.shutdown()

    logger.info("")

# 
def create_default_analysis_result(alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """"""
    return {
        'success': True,
        'alert_id': alert_data.get('alert_id', 'unknown'),
        'timestamp': time.time(),
        'routing_analysis': {
            'router_id': 'fallback_router',
            'selected_routes': [],
            'routing_confidence': 0.5,
            'routing_details': {
                'selected_route': 'unknown',
                'target_agent': 'unknown',
                'route_scores': {},
                'analysis': ''
            }
        },
        'expert_analysis': {
            'total_experts': 0,
            'successful_experts': 0,
            'expert_results': []
        },
        'fusion_analysis': {
            'final_attack_type': alert_data.get('attack_type', ''),
            'final_confidence': 0.3,
            'final_risk_score': 5.0,
            'consensus_level': 0.0,
            'conflict_resolution': 'default',
            'contributing_experts': [],
            'reasoning_summary': ''
        },
        'overall_assessment': {
            'risk_score': 5.0,
            'threat_level': 'medium',
            'recommended_actions': [
                'Record the event for trend analysis',
                'Confirm the finding is not a scanner false positive',
            ]
        },
        'processing_chain': [
            {
                'stage': 'fallback_processing',
                'agent': 'system',
                'processing_time': 0.01,
                'success': True,
                'confidence': 0.3
            }
        ],
        'result': {}  # result
    }

# 
async def require_initialized_system():
    if not multi_agent_system or not multi_agent_system.is_initialized:
        raise HTTPException(status_code=503, detail="Multi-agent system is not initialized")

    return {
        'multi_agent_system': multi_agent_system.get_system_status(),
        'rag_analyzer': rag_analyzer.get_enhancer_statistics() if rag_analyzer else None,
        'log_parser': log_parser is not None
    }

# API
@app.get("/", response_model=Dict[str, Any])
async def root():
    """"""
    return {
        "message": "API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now()
    }

@app.post("/api/v1/analyze/alert", response_model=AnalysisResponse)
async def analyze_single_alert(
    request: AlertAnalysisRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(require_api_key),
):
    """"""
    request_id = str(uuid.uuid4())
    start_time = time.time()

    try:
        logger.info(f": {request_id}")
        print(f"DEBUG: : {request_id}")
        print(f"DEBUG: :", multi_agent_system is not None)
        print(f"DEBUG: :", multi_agent_system.is_initialized if multi_agent_system else False)
        print(f"DEBUG: ... : {request.alert_data}")

        # 
        if not multi_agent_system or not multi_agent_system.is_initialized:
            print("DEBUG: ")
            raise HTTPException(status_code=503, detail="")

        # 
        print("DEBUG: multi_agent_system.analyze_alert...")
        analysis_result = await multi_agent_system.analyze_alert(request.alert_data)
        print(f"DEBUG: : {analysis_result}")
        print(f"DEBUG: : {type(analysis_result)}")

        if not analysis_result:
            print("DEBUG: ")
            analysis_result = create_default_analysis_result(request.alert_data)

        if not analysis_result.get('success'):
            print(f"DEBUG: : {analysis_result.get('error_message', '')}")
            raise HTTPException(
                status_code=500,
                detail=f": {analysis_result.get('error_message', '')}"
            )

        print(f"DEBUG: : {analysis_result}")

        # RAG
        if request.enable_rag_enhancement and rag_analyzer:
            try:
                rag_result = rag_analyzer.enhance_analysis(
                    request.alert_data,
                    analysis_result
                )
                analysis_result['rag_enhancement'] = rag_result
            except Exception as e:
                logger.warning(f"RAG: {e}")
                analysis_result['rag_enhancement'] = {
                    'success': False,
                    'error_message': str(e)
                }

        # 
        background_tasks.add_task(
            log_analysis_result,
            request_id,
            request.alert_data,
            analysis_result,
            time.time() - start_time
        )

        processing_time = time.time() - start_time

        # analysis_resultdatetimeJSON
        def clean_datetime(obj, memo=None):
            """datetime"""
            if memo is None:
                memo = set()

            obj_id = id(obj)
            if obj_id in memo:
                return f"[Circular Reference: {type(obj).__name__}]"
            memo.add(obj_id)

            # 
            if hasattr(obj, '__name__') and callable(obj):
                return f"[Function: {obj.__name__}]"
            elif str(type(obj)) == "<class 'mappingproxy'>":
                return "[MappingProxy]"
            elif hasattr(obj, '__module__') and hasattr(obj, '__name__'):
                return f"[Class: {obj.__module__}.{obj.__name__}]"
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: clean_datetime(v, memo) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [clean_datetime(item, memo) for item in obj]
            elif isinstance(obj, tuple):
                return tuple(clean_datetime(item, memo) for item in obj)
            elif hasattr(obj, '__dict__'):
                # 
                return clean_datetime(obj.__dict__, memo)
            elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
                try:
                    return [clean_datetime(item, memo) for item in obj]
                except:
                    return f"[Unserializable: {type(obj).__name__}]"
            else:
                # 
                try:
                    return str(obj)
                except:
                    return f"[Unserializable: {type(obj).__name__}]"

        cleaned_result = clean_datetime(analysis_result)

        # result
        if 'result' not in analysis_result or not analysis_result['result']:
            analysis_result['result'] = analysis_result.copy()

        # JSONResponsePydantic
        response_data = {
            "success": True,
            "result": cleaned_result or analysis_result.get('result', {}),
            "processing_time": processing_time,
            "request_id": request_id,
            "timestamp": datetime.now().isoformat()
        }

        # JSON
        response_json = safe_json_dumps(response_data)
        return JSONResponse(
            status_code=200,
            content=json.loads(response_json)
        )

    except HTTPException:
        raise
    except Exception as e:
        processing_time = time.time() - start_time
        logger.error(f": {e}")

        return AnalysisResponse(
            success=False,
            error_message=str(e),
            processing_time=processing_time,
            request_id=request_id,
            timestamp=datetime.now()
        )

@app.post("/api/v1/analyze/batch", response_model=List[AnalysisResponse])
async def analyze_batch_alerts(
    request: BatchAnalysisRequest,
    _: None = Depends(require_api_key),
):
    """"""
    try:
        logger.info(f" {len(request.alert_list)} ")

        # 
        if not multi_agent_system or not multi_agent_system.is_initialized:
            raise HTTPException(status_code=503, detail="")

        # 
        if len(request.alert_list) > 100:
            raise HTTPException(status_code=400, detail="100")

        # 
        results = []
        for i, alert_data in enumerate(request.alert_list):
            request_id = str(uuid.uuid4())
            start_time = time.time()

            try:
                # 
                analysis_result = await multi_agent_system.analyze_alert(alert_data)

                # RAG
                if request.enable_rag_enhancement and rag_analyzer:
                    try:
                        rag_result = rag_analyzer.enhance_analysis(alert_data, analysis_result)
                        analysis_result['rag_enhancement'] = rag_result
                    except Exception as e:
                        logger.warning(f"RAG ({i+1}): {e}")

                processing_time = time.time() - start_time

                results.append(AnalysisResponse(
                    success=True,
                    result=analysis_result,
                    processing_time=processing_time,
                    request_id=request_id,
                    timestamp=datetime.now()
                ))

            except Exception as e:
                processing_time = time.time() - start_time
                results.append(AnalysisResponse(
                    success=False,
                    error_message=str(e),
                    processing_time=processing_time,
                    request_id=request_id,
                    timestamp=datetime.now()
                ))

        logger.info(f": {sum(1 for r in results if r.success)}, "
                   f": {sum(1 for r in results if not r.success)}")

        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f": {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/parse/log")
async def parse_log_file(
    file_path: Optional[str] = None,
    file: Optional[UploadFile] = File(default=None),
    _: None = Depends(require_api_key),
):
    """Parse an Excel/CSV log. Paths must resolve under data/; uploads are written there first."""
    tmp_path = None
    try:
        if not log_parser:
            raise HTTPException(status_code=503, detail="Log parser is not initialized")

        if file is not None:
            suffix = Path(file.filename or "upload.xlsx").suffix.lower() or ".xlsx"
            upload_dir = DEFAULT_DATA_DIR / "uploads"
            upload_dir.mkdir(parents=True, exist_ok=True)
            tmp_path = upload_dir / f"{uuid.uuid4().hex}{suffix}"
            content = await file.read()
            tmp_path.write_bytes(content)
            resolved = resolve_log_path(str(tmp_path))
        elif file_path:
            resolved = resolve_log_path(file_path)
        else:
            raise HTTPException(status_code=400, detail="Provide file_path under data/ or upload a file")

        logger.info(f"Parsing log: {resolved}")
        parsed_alerts = log_parser.parse_excel_log(str(resolved))

        if not parsed_alerts:
            return {
                "success": True,
                "message": "",
                "parsed_count": 0,
                "alerts": []
            }

        # 
        alerts_dict = []
        for alert in parsed_alerts:
            alerts_dict.append({
                'timestamp': alert.timestamp.isoformat(),
                'source_ip': alert.source_ip,
                'target_ip': alert.target_ip,
                'attack_type': alert.attack_type,
                'attack_stage': alert.attack_stage,
                'threat_level': alert.threat_level,
                'protocol': alert.protocol,
                'payload': alert.payload,
                'features': alert.features
            })

        return {
            "success": True,
            "message": f" {len(alerts_dict)} ",
            "parsed_count": len(alerts_dict),
            "alerts": alerts_dict[:100]  # 100
        }

    except UnsafePathError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Log parse failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

@app.get("/api/v1/system/status", response_model=SystemStatusResponse)
async def get_system_status_endpoint(_: None = Depends(require_api_key)):
    """"""
    try:
        # 
        multi_agent_status = multi_agent_system.get_system_status() if multi_agent_system else {"status": "not_initialized"}
        rag_status = rag_analyzer.get_enhancer_statistics() if rag_analyzer else {"status": "not_initialized"}
        health_check = multi_agent_system.health_check() if multi_agent_system else {"overall_health": "unknown"}

        return SystemStatusResponse(
            system_status={
                "is_initialized": multi_agent_system.is_initialized if multi_agent_system else False,
                "health_check": health_check,
                "uptime": time.time()
            },
            agent_status=multi_agent_status,
            rag_status=rag_status,
            performance_metrics={
                "total_requests": multi_agent_status.get("performance_metrics", {}).get("total_requests", 0),
                "success_rate": _calculate_success_rate(multi_agent_status),
                "average_response_time": multi_agent_status.get("performance_metrics", {}).get("average_response_time", 0.0)
            }
        )

    except Exception as e:
        logger.error(f": {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/threat-intel/recent")
async def get_recent_threat_intel(days: int = 7, _: None = Depends(require_api_key)):
    """"""
    try:
        if not rag_analyzer or not rag_analyzer.threat_retriever:
            raise HTTPException(status_code=503, detail="")

        recent_intel = rag_analyzer.threat_retriever.get_recent_intel(days)

        return {
            "success": True,
            "days": days,
            "count": len(recent_intel),
            "threat_intel": recent_intel
        }

    except Exception as e:
        logger.error(f": {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/threat-intel/search")
async def search_threat_intel(query: str, top_k: int = 5, _: None = Depends(require_api_key)):
    """"""
    try:
        if not rag_analyzer or not rag_analyzer.threat_retriever:
            raise HTTPException(status_code=503, detail="")

        threat_intel = rag_analyzer.threat_retriever.retrieve(query, top_k)

        return {
            "success": True,
            "query": query,
            "top_k": top_k,
            "count": len(threat_intel),
            "threat_intel": threat_intel
        }

    except Exception as e:
        logger.error(f": {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/metrics")
async def get_performance_metrics(_: None = Depends(require_api_key)):
    """"""
    try:
        if not multi_agent_system:
            raise HTTPException(status_code=503, detail="")

        metrics = multi_agent_system.get_system_status()

        return {
            "success": True,
            "metrics": metrics["performance_metrics"],
            "agent_metrics": metrics["individual_agent_metrics"],
            "system_health": multi_agent_system.health_check()
        }

    except Exception as e:
        logger.error(f": {e}")
        raise HTTPException(status_code=500, detail=str(e))

# 
def _calculate_success_rate(multi_agent_status: Dict[str, Any]) -> float:
    """"""
    try:
        metrics = multi_agent_status.get("performance_metrics", {})
        total = metrics.get("total_requests", 0)
        successful = metrics.get("successful_requests", 0)

        if total == 0:
            return 0.0

        success_rate = (successful / total) * 100  # 
        print(f"[DEBUG] : {successful}/{total} = {success_rate}%")  # 
        logger.info(f": {successful}/{total} = {success_rate}%")
        return success_rate
    except Exception as e:
        logger.error(f": {e}")
        return 0.0

async def log_analysis_result(request_id: str, alert_data: Dict[str, Any],
                            analysis_result: Dict[str, Any], processing_time: float):
    """"""
    try:
        log_entry = {
            "request_id": request_id,
            "alert_type": alert_data.get("attack_type", "unknown"),
            "success": analysis_result.get("success", False),
            "processing_time": processing_time,
            "risk_score": (
                (analysis_result.get("overall_assessment") or {}).get("risk_score")
                or ((analysis_result.get("result") or {}).get("overall_assessment") or {}).get("risk_score")
                or 0
            ),
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f": {log_entry}")

    except Exception as e:
        logger.error(f": {e}")

# 
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """"""
    logger.error(f": {exc}")
    error_content = {
        "success": False,
        "error_message": "",
        "timestamp": datetime.now().isoformat(),
        "error_type": type(exc).__name__
    }

    try:
        # JSON
        error_json = safe_json_dumps(error_content)
        return JSONResponse(
            status_code=500,
            content=json.loads(error_json)
        )
    except Exception as e:
        logger.error(f": {e}")
        # 
        return JSONResponse(
            status_code=500,
            content={"success": False, "error_message": ""}
        )

if __name__ == "__main__":
    import uvicorn

    parser = argparse.ArgumentParser(description="Network threat analysis API")
    parser.add_argument("--host", default=os.getenv("API_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("API_PORT", "8000")))
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    uvicorn.run(
        "src.api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
        access_log=True,
    )