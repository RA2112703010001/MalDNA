import os
import sys
import argparse
import logging
import click
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS  # Import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask.cli import AppGroup, with_appcontext

# ✅ Load environment variables
load_dotenv()

# ✅ MalDNA ASCII Logo
MALDNA_LOGO = """
███╗   ███╗ █████╗ ██╗      ██████╗ ███╗   ██╗ █████╗ 
████╗ ████║██╔══██╗██║     ██╔═══██╗████╗  ██║██╔══██╗
██╔████╔██║███████║██║     ██║   ██║██╔██╗ ██║███████║
██║╚██╔╝██║██╔══██║██║     ██║   ██║██║╚██╗██║██╔══██║
██║ ╚═╝ ██║██║  ██║███████╗╚██████╔╝██║ ╚████║██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
🚀 Advanced DNA-Powered Malware Analysis Platform 🚀
"""

# ✅ Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("maldna_startup.log", mode="a", encoding="utf-8")],
)
logger = logging.getLogger(__name__)

# ✅ Static Frontend Path
FRONTEND_PATH = os.path.abspath("frontend/pages")

# ✅ Flask-Limiter with Redis (Rate Limiting)
rate_limit_storage_uri = os.getenv("RATELIMIT_STORAGE_URI", "redis://localhost:6379")
limiter = Limiter(key_func=get_remote_address, storage_uri=rate_limit_storage_uri)


def register_blueprints(app):
    """Register all Flask Blueprints (Controllers)."""
    try:
        from app.controllers.malwareController import malware_bp
        from app.controllers.dnaController import dna_bp
        from app.controllers.lineageController import lineage_bp
        from app.controllers.forensicController import forensic_bp
        from app.controllers.realtimeController import realtime_bp
        from app.controllers.userController import user_bp
        from app.controllers.threatController import threat_bp
        from app.controllers.reportController import report_bp
        from app.controllers.auditController import audit_bp
        from app.controllers.featureController import feature_bp
        from app.controllers.hybridAnalysis import hybrid_analysis_bp
        from app.controllers.blockchainservice import blockchain_bp
        from app.controllers.dashboardController import dashboard_bp
        from app.controllers.datasetController import dataset_bp
    except ImportError as e:
        logger.error(f"❌ Error importing controllers: {e}")
        sys.exit(1)

    blueprints = [
        (malware_bp, "/api/malware"),
        (dna_bp, "/api/dna"),
        (lineage_bp, "/api/lineage"),
        (forensic_bp, "/api/forensics"),
        (realtime_bp, "/api/realtime"),
        (user_bp, "/api/user"),
        (threat_bp, "/api/threat"),
        (report_bp, "/api/report"),
        (audit_bp, "/api/audit"),
        (feature_bp, "/api/features"),
        (hybrid_analysis_bp, "/api/hybrid-analysis"),
        (blockchain_bp, "/api/blockchain"),
        (dashboard_bp, "/api/dashboard"),
        (dataset_bp, "/api/dataset"),
    ]

    for blueprint, url_prefix in blueprints:
        try:
            if blueprint.name in app.blueprints:
                logger.warning(f"⚠️ Skipping duplicate blueprint: {blueprint.name}")
                continue
            app.register_blueprint(blueprint, url_prefix=url_prefix)
            logger.info(f"✅ Registered Blueprint: {blueprint.name} at {url_prefix}")
        except Exception as e:
            logger.error(f"❌ Failed to Register Blueprint {blueprint.name}: {e}")


def create_app(env="development"):
    """Create and configure the Flask application."""
    print(MALDNA_LOGO)
    logger.info("🚀 Starting MalDNA Backend...")

    app = Flask(__name__, static_folder=FRONTEND_PATH)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "05e5c054534a0bb3cb7460775ce31fa51d6040e27898885a9255a3e961a177ed")
    app.config["MONGODB_URI"] = os.getenv("MONGODB_URI", "mongodb://localhost:27017/maldna_db")

    # ✅ Enable CORS (Allow frontend on 127.0.0.1:8080)
    frontend_origin = os.getenv("FRONTEND_ORIGIN", "http://127.0.0.1:8080")
    CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": frontend_origin}})

    # ✅ Initialize Services
    limiter.init_app(app)

    # ✅ Register Controllers
    register_blueprints(app)

    # ✅ Register CLI Commands
    app.cli.add_command(cli)

    @app.route("/")
    def home():
        return jsonify({"message": "🚀 MalDNA Backend is running!"}), 200

    return app


# ✅ CLI Command Group
cli = AppGroup("cli")


@cli.command("analyze")
@click.argument("file_path")
@with_appcontext
def analyze_sample(file_path):
    """Perform Static, Dynamic, and Hybrid Malware Analysis."""
    from app.utils.featureExtraction import FeatureExtractor
    from app.services.dynamicAnalysis import DynamicAnalysisService
    from app.services.hybridAnalysis import HybridAnalysisService
    import magic

    logger.info(f"🔍 Analyzing file: {file_path}")

    if not os.path.exists(file_path):
        logger.error("❌ File not found")
        return

    mime = magic.Magic(mime=True)
    file_type = mime.from_file(file_path)
    logger.info(f"📂 Detected File Type: {file_type}")

    extractor = FeatureExtractor()
    hybrid_analyzer = HybridAnalysisService()

    static_features = extractor.extract_static_features(file_path)

    try:
        dynamic_features = DynamicAnalysisService.generate_dynamic_analysis_report(file_path)
    except ValueError as e:
        logger.error(f"⚠️ Dynamic Analysis Error: {e}")
        dynamic_features = {"error": str(e)}

    result = hybrid_analyzer.perform_analysis(file_path)

    logger.info(f"🔎 Static Features: {static_features}")
    logger.info(f"🔎 Dynamic Features: {dynamic_features}")
    logger.info(f"🔎 Hybrid Features: {result}")


@cli.command("train-ml-model")
@click.option("--dataset", required=True, help="Path to dataset")
@click.option("--model", default="random_forest", help="Model type")
@click.option("--test_size", default=0.2, type=float, help="Test dataset size")
@with_appcontext
def train_ml_model(dataset, model, test_size):
    """Train ML model from CLI."""
    from ml.training.trainML import MLTrainer

    try:
        trainer = MLTrainer(dataset=dataset, model_type=model, test_size=test_size)
        result = trainer.train()

        if result["status"] == "success":
            click.secho(f"✅ Model trained successfully!", fg="green")
            click.echo(f"📁 Model saved to: {result['model_path']}")
            click.echo(f"📜 Training log saved to: {result['log_path']}")
            click.echo(f"🎯 Accuracy: {result['accuracy']:.4f}")
        else:
            click.secho(f"❌ Training failed: {result['error']}", fg="red")

    except Exception as e:
        click.secho(f"🔥 Critical error during training: {str(e)}", fg="bright_red")


@cli.command("train-dl")
@with_appcontext
def train_dl_model():
    """Train a deep learning model via CLI."""
    from training.trainDL import train
    logger.info("🔄 Starting Deep Learning training...")
    try:
        train()
        logger.info("✅ Deep Learning model training completed.")
    except Exception as e:
        logger.error(f"❌ DL Training failed: {e}")


def main():
    """Main entry point for running the application."""
    parser = argparse.ArgumentParser(description="MalDNA Backend Application")
    parser.add_argument("--env", choices=["development", "production", "testing"], default="testing")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--debug", action="store_true")
    args, _ = parser.parse_known_args()

    app = create_app(args.env)
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
from app.models.malwareModel import MalwareModel

def fix_invalid_indexes_on_startup():
    try:
        # Fix invalid indexes on startup
        MalwareModel.fix_invalid_indexes()
        logger.info("✅ Invalid indexes fixed during app startup.")
    except Exception as e:
        logger.error(f"❌ Error fixing indexes during startup: {str(e)}")


if __name__ == "__main__":
    main()
    fix_invalid_indexes_on_startup()

