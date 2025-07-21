import os
import logging
import subprocess
from typing import List, Dict, Any
from functools import wraps
from datetime import datetime
import requests
import pefile
from dotenv import load_dotenv
from collections import Counter
import random
import pefile
import hashlib
from app.models.malwareModel import MalwareModel, MalwareMetadata
from app.services.dnaService import DNAAnalysisService
from app.utils.featureExtraction import FeatureExtractor, extract_strings, detect_obfuscated_strings, extract_ips_and_urls, detect_packers,is_probably_packed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Configuration constants
RADARE2_PATH = os.getenv("RADARE2_PATH", "/usr/bin/radare2")
UPLOAD_FOLDER = os.getenv("UPLOAD_FOLDER", "/home/kali/MalDNA/dataset/")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "b120f83731479498b41b4b98a73d1a7299963eea910778190d40c017641cf252")

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def validate_file_path(func):
    """Decorator to validate file path before analysis."""
    @wraps(func)
    def wrapper(file_path, *args, **kwargs):
        if not os.path.exists(file_path):
            logger.error(f"❌ File not found: {file_path}")
            raise FileNotFoundError(f"File not found: {file_path}")
        if not os.access(file_path, os.R_OK):
            logger.error(f"❌ File not readable: {file_path}")
            raise PermissionError(f"File not readable: {file_path}")
        return func(file_path, *args, **kwargs)
    return wrapper

def safe_subprocess_run(command: List[str]) -> subprocess.CompletedProcess:
    """Safely execute a subprocess command with error handling."""
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=300, check=True
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Subprocess command failed: {' '.join(command)} | Error: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        logger.error(f"❌ Subprocess command timed out: {' '.join(command)}")
        raise

@validate_file_path
def extract_opcodes(file_path: str) -> str:
    """Extracts opcodes using Radare2."""
    try:
        result = subprocess.run([RADARE2_PATH, "-qc", "pd 100", file_path], capture_output=True, text=True)
        logger.info(f"✅ Extracted Opcodes:\n{result.stdout[:500]}...")
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"❌ Opcode extraction failed for {file_path}: {e}")
        return f"Error extracting opcodes: {e}"

@validate_file_path
def detect_obfuscation(file_path: str) -> str:
    """Detect obfuscation using Radare2 string analysis."""
    try:
        result = subprocess.run([RADARE2_PATH, "-qc", "izz", file_path], capture_output=True, text=True)
        return "Obfuscation detected" if "encrypt" in result.stdout.lower() else "No obfuscation found"
    except Exception as e:
        logger.error(f"❌ Obfuscation detection failed for {file_path}: {e}")
        return f"Error detecting obfuscation: {e}"

@validate_file_path
def analyze_strings(file_path: str) -> List[str]:
    """Extract strings from binary."""
    try:
        result = safe_subprocess_run(["strings", file_path])
        return result.stdout.splitlines()
    except Exception as e:
        logger.error(f"❌ String analysis failed for {file_path}: {e}")
        raise

@validate_file_path
def analyze_pe_file(file_path: str) -> Dict[str, Any]:
    """Extract PE file metadata."""
    try:
        pe = pefile.PE(file_path)
        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "sections": [section.Name.decode().strip("\x00") for section in pe.sections],
            "imports": [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else [],
            "exports": [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else []
        }
    except Exception as e:
        logger.error(f"❌ PE file analysis failed for {file_path}: {e}")
        raise

@validate_file_path
def extract_file_metadata(file_path: str) -> Dict[str, Any]:
    try:
        # Load PE file
        pe = pefile.PE(file_path)

        # File Hashes
        with open(file_path, 'rb') as f:
            file_data = f.read()
            file_hashes = {
                "md5": hashlib.md5(file_data).hexdigest(),
                "sha1": hashlib.sha1(file_data).hexdigest(),
                "sha256": hashlib.sha256(file_data).hexdigest(),
            }

        # Sections
        file_sections = [section.Name.decode(errors='ignore').strip('\x00') for section in pe.sections]

        # Entry Point
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

        # Imports
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode()
                for imp in entry.imports:
                    imports.append({"dll": dll, "name": imp.name.decode() if imp.name else None})

        # Exports
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name]

        # Strings
        strings = extract_strings(file_data)
        suspicious_strings = [s for s in strings if "cmd.exe" in s or "http://" in s or "powershell" in s]
        obfuscated_strings = detect_obfuscated_strings(strings)

        # Network indicators
        urls, ips = extract_ips_and_urls(strings)

        # DLL Characteristics
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics

        # Entropy
        entropy = sum([section.get_entropy() for section in pe.sections]) / len(pe.sections)

        # Version Info
        try:
            version_info = {}
            for fileinfo in pe.FileInfo:
                for entry in fileinfo:
                    if hasattr(entry, 'StringTable'):
                        for st in entry.StringTable:
                            version_info.update(st.entries)
        except:
            version_info = {}

        return {
            "file_size": os.path.getsize(file_path),
            "file_extension": os.path.splitext(file_path)[1],
            "creation_time": os.path.getctime(file_path),
            "modification_time": os.path.getmtime(file_path),
            "entropy": entropy,
            "file_sections": file_sections,
            "entry_point": entry_point,
            "imports": imports,
            "exports": exports,
            "dll_characteristics": dll_characteristics,
            "suspicious_strings": suspicious_strings,
            "obfuscated_strings": obfuscated_strings,
            "embedded_urls": urls,
            "embedded_ips": ips,
            "file_hashes": file_hashes,
            "file_version_info": version_info,
            "company_name": version_info.get("CompanyName"),
            "product_name": version_info.get("ProductName"),
            "file_version": version_info.get("FileVersion"),
            "original_filename": version_info.get("OriginalFilename"),
            "packers_detected": detect_packers(pe),  # You'll need to define this
            "is_packed": is_probably_packed(pe),     # You'll need to define this
        }

    except Exception as e:
        logger.error(f"❌ File metadata extraction error: {e}")
        return {}


@validate_file_path
def check_virustotal_scan(file_path: str) -> Dict[str, Any]:
    """Query VirusTotal with file SHA256 hash."""
    import hashlib

    def get_sha256(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    sha256 = get_sha256(file_path)
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "sha256": sha256,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            }
        elif response.status_code == 404:
            return {"sha256": sha256, "error": "File not found on VirusTotal"}
        else:
            return {"sha256": sha256, "error": f"Unexpected response: {response.status_code}"}
    except Exception as e:
        logger.error(f"❌ VirusTotal scan failed: {e}")
        return {"sha256": sha256, "error": str(e)}

def generate_static_analysis_report(file_path: str) -> Dict[str, Any]:
    """Generate a comprehensive static analysis report."""
    report = {
        "file_path": file_path,
        "timestamp": datetime.utcnow().isoformat(),
        "analysis_results": {},
        "errors": []
    }

    analysis_functions = [
        extract_opcodes,
        analyze_strings,
        analyze_pe_file,
        detect_obfuscation,
        extract_file_metadata,
        check_virustotal_scan  # Added VirusTotal analysis
    ]

    for func in analysis_functions:
        try:
            report["analysis_results"][func.__name__] = func(file_path)
        except Exception as e:
            report["errors"].append({"function": func.__name__, "error": str(e)})
            logger.error(f"❌ {func.__name__} failed: {e}")

    try:
        features = FeatureExtractor.extract_features_for_ml(file_path)
        report["analysis_results"]["dna_fingerprint"] = DNAAnalysisService.generate_dna_fingerprint(features)
    except Exception as e:
        report["errors"].append({"function": "dna_fingerprint_generation", "error": str(e)})

    return report

class StaticAnalysisService:
    """Service class for static analysis."""
    @classmethod
    def analyze(cls, file_path: str) -> Dict[str, Any]:
        dna_reference_id = str(random.getrandbits(128))
        file_hash = str(random.getrandbits(128))

        malware_metadata = MalwareMetadata(
            sample_id=str(random.getrandbits(128)),
            filename=os.path.basename(file_path),
            file_path=file_path,
            os_version='Linux',
            architecture='x64',
            country_origin='US',
            collection_method='manual',
            threat_actor='Unknown',
            detection_status='not_detected',
            timestamp=datetime.utcnow()
        )
        malware_metadata.save()
        analysis_report = generate_static_analysis_report(file_path)
        
        # Extract all relevant features from the report and save them to the database
        malware_metadata.update(
            set__entropy=analysis_report.get('analysis_results', {}).get('entropy'),
            set__file_sections=analysis_report.get('analysis_results', {}).get('file_sections', []),
            set__entry_point=analysis_report.get('analysis_results', {}).get('entry_point'),
            set__packers_detected=analysis_report.get('analysis_results', {}).get('packers_detected'),
            set__is_packed=analysis_report.get('analysis_results', {}).get('is_packed', False),
            set__suspicious_strings=analysis_report.get('analysis_results', {}).get('suspicious_strings', []),
            set__obfuscated_strings=analysis_report.get('analysis_results', {}).get('obfuscated_strings', []),
            set__embedded_urls=analysis_report.get('analysis_results', {}).get('embedded_urls', []),
            set__embedded_ips=analysis_report.get('analysis_results', {}).get('embedded_ips', []),
            set__file_version_info=analysis_report.get('analysis_results', {}).get('file_version_info'),
            set__company_name=analysis_report.get('analysis_results', {}).get('company_name'),
            set__product_name=analysis_report.get('analysis_results', {}).get('product_name'),
            set__file_version=analysis_report.get('analysis_results', {}).get('file_version'),
            set__original_filename=analysis_report.get('analysis_results', {}).get('original_filename'),
            set__imports=analysis_report.get('analysis_results', {}).get('imports', []),
            set__exports=analysis_report.get('analysis_results', {}).get('exports', []),
            set__resources=analysis_report.get('analysis_results', {}).get('resources', []),
            set__dll_characteristics=analysis_report.get('analysis_results', {}).get('dll_characteristics'),
            set__import_hash=analysis_report.get('analysis_results', {}).get('import_hash'),
            set__opcode_sequence=analysis_report.get('analysis_results', {}).get('opcode_sequence', []),
            set__suspicious_opcode_patterns=analysis_report.get('analysis_results', {}).get('suspicious_opcode_patterns', []),
            set__nopsled_detected=analysis_report.get('analysis_results', {}).get('nopsled_detected', False),
            set__file_size=analysis_report.get('analysis_results', {}).get('file_size'),
            set__hashes=analysis_report.get('analysis_results', {}).get('hashes', {}),
            set__sha256=analysis_report.get('analysis_results', {}).get('sha256'),
            set__file_type=analysis_report.get('analysis_results', {}).get('file_type')
        )
        
        return analysis_report

