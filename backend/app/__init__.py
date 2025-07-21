import os
import logging
from logging.handlers import RotatingFileHandler
from typing import Optional
from datetime import datetime

from flask import Flask
from flask_cors import CORS
from flask_mongoengine import MongoEngine
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix

from app.config import Config, load_config
from app.services.blockchainService import BlockchainService

import warnings

warnings.simplefilter("ignore", UserWarning)

# ✅ Configure Logging (Separate Log File Per Process)
log_path = f"logs/maldna_app_{os.getpid()}.log"
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        RotatingFileHandler(log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"),
    ],
)

logger = logging.getLogger(__name__)

# ✅ Initialize Database & JWTManager
db = MongoEngine()
jwt = JWTManager()

# ✅ API Rate Limiting (User-Based)
def get_jwt_identity_or_ip():
    from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
    try:
        verify_jwt_in_request()
        return get_jwt_identity()
    except:
        return get_remote_address()

limiter = Limiter(key_func=get_jwt_identity_or_ip)

def create_app(config_name: Optional[str] = None) -> Flask:
    """Initializes the MalDNA Flask app with necessary configurations."""

    app_config = load_config(config_name or "default")
    app = Flask(__name__)
    app.config.from_object(app_config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    # ✅ Enable CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ✅ Initialize extensions
    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    # ✅ Import and Register Controllers
    from app.controllers import (
        malwareController, dnaController, lineageController, forensicController,
        realtimeController, userController, threatController, reportController,
        auditController, featureController, hybridAnalysis, blockchainservice, dashboardController
    )

    # ✅ Blueprint Mapping
    blueprints = {
        "malware_bp": (malwareController.malware_bp, "/api/malware"),
        "dna_bp": (dnaController.dna_bp, "/api/dna"),
        "lineage_bp": (lineageController.lineage_bp, "/api/lineage"),
        "forensic_bp": (forensicController.forensic_bp, "/api/forensics"),
        "realtime_bp": (realtimeController.realtime_bp, "/api/realtime"),
        "user_bp": (userController.user_bp, "/api/user"),
        "threat_bp": (threatController.threat_bp, "/api/threat"),
        "report_bp": (reportController.report_bp, "/api/report"),
        "audit_bp": (auditController.audit_bp, "/api/audit"),
        "feature_bp": (featureController.feature_bp, "/api/features"),
        "hybrid_analysis_bp": (hybridAnalysis.hybrid_analysis_bp, "/api/hybrid-analysis"),
        "blockchain_bp": (blockchainservice.blockchain_bp, "/api/blockchain"),
        "dashboard_bp": (dashboardController.dashboard_bp, "/api/dashboard"),
    }

    # ✅ Register Blueprints
    for name, (blueprint, url_prefix) in blueprints.items():
        if name in app.blueprints:
            logger.warning(f"⚠️ Skipping duplicate blueprint: {name}")
            continue
        limiter.limit("50 per minute")(blueprint)
        app.register_blueprint(blueprint, url_prefix=url_prefix)

    # ✅ Initialize Blockchain Service
    with app.app_context():
        try:
            app.extensions["blockchain_service"] = BlockchainService()
            logger.info("✅ Blockchain service initialized successfully")
        except Exception as e:
            logger.error(f"❌ Blockchain service initialization failed: {e}")
            app.extensions["blockchain_service"] = None

    # ✅ Debugging: Log All Registered Routes
    with app.app_context():
        logger.info("✅ Registered Routes & Endpoints:")
        for rule in app.url_map.iter_rules():
            logger.info(f"📌 Route: {rule}, Endpoint: {rule.endpoint}")

    return app

# ✅ Initialize the Flask Application
app = create_app()
logger.info(f"🚀 MalDNA Backend Initialized: {datetime.utcnow().isoformat()}")

