import os
import json
import numpy as np
import pandas as pd
import logging
import hashlib
import re
import string
import pefile
from typing import Dict, List, Union, Optional, Tuple, Any
from sklearn.preprocessing import StandardScaler, MinMaxScaler, RobustScaler
from sklearn.decomposition import PCA
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.utils import resample
from collections import Counter
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("feature_extraction.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Data directory setup
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)

# Utility Functions
def is_probably_packed(pe: pefile.PE) -> bool:
    high_entropy_threshold = 7.5
    for section in pe.sections:
        if section.get_entropy() > high_entropy_threshold:
            return True
    suspicious_imports = ["LoadLibrary", "VirtualAlloc", "GetProcAddress", "CreateProcess", "ExitProcess"]
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and imp.name.decode().startswith(tuple(suspicious_imports)):
                return True
    return False

def detect_packers(pe: pefile.PE) -> list:
    packers = []
    if b'UPX' in pe.get_memory_mapped_image():
        packers.append("UPX")
    if any(section.Name.startswith(b'.aspack') for section in pe.sections):
        packers.append("ASPack")
    if any("Themida" in str(entry.dll) for entry in pe.DIRECTORY_ENTRY_IMPORT if hasattr(entry, 'dll')):
        packers.append("Themida")
    return packers

def extract_strings(binary_data: bytes, min_length: int = 4) -> List[str]:
    result = []
    current = ""
    for byte in binary_data:
        char = chr(byte)
        if char in string.printable:
            current += char
            continue
        if len(current) >= min_length:
            result.append(current)
        current = ""
    if len(current) >= min_length:
        result.append(current)
    return result

def detect_obfuscated_strings(strings: List[str], threshold: float = 0.6) -> List[str]:
    def shannon_entropy(s: str) -> float:
        prob = [float(s.count(c)) / len(s) for c in set(s)]
        return -sum(p * np.log2(p) for p in prob if p > 0)
    return [s for s in strings if len(s) > 8 and shannon_entropy(s) > threshold]

def extract_ips_and_urls(strings: List[str]) -> Tuple[List[str], List[str]]:
    url_pattern = re.compile(r'https?://[^\s\'"<>]+')
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    urls, ips = [], []
    for s in strings:
        urls += url_pattern.findall(s)
        ips += ip_pattern.findall(s)
    return list(set(urls)), list(set(ips))

# Feature Extractor Class
class FeatureExtractor:
    def __init__(self, scaling_method="standard", pca_components=5, feature_selection_k=10):
        self.scaling_methods = {
            "standard": StandardScaler(),
            "minmax": MinMaxScaler(),
            "robust": RobustScaler()
        }
        self.scaler = self.scaling_methods.get(scaling_method, StandardScaler())
        self.feature_selector = SelectKBest(f_classif, k=feature_selection_k)
        self.pca = PCA(n_components=pca_components)

        self.static_features = []
        self.dynamic_features = []
        self.behavioral_features = []

    def extract_static_features(self, binary_path: str, advanced=False) -> Dict:
        try:
            static_data = {
                "file_size": os.path.getsize(binary_path),
                "file_extension": os.path.splitext(binary_path)[1],
                "creation_time": os.path.getctime(binary_path),
                "modification_time": os.path.getmtime(binary_path),
                "entropy": self._calculate_entropy(binary_path)
            }
            if advanced:
                static_data.update(self._advanced_static_analysis(binary_path))
            self.static_features.append(static_data)
            logger.info(f"Extracted static features from {binary_path}")
            return static_data
        except Exception as e:
            logger.error(f"Static feature extraction error: {e}")
            raise

    def _calculate_entropy(self, file_path: str) -> float:
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                if not data:
                    return 0.0
                byte_counts = Counter(data)
                total_bytes = len(data)
                return -sum((count / total_bytes) * np.log2(count / total_bytes) for count in byte_counts.values())
        except Exception as e:
            logger.error(f"Entropy calculation error: {e}")
            return 0.0

    def _advanced_static_analysis(self, binary_path: str) -> Dict:
        return {
            "suspicious_strings": [],
            "imported_libraries": [],
            "code_sections": {},
            "anti_debugging_techniques": []
        }

    def extract_dynamic_features(self, file_path: str, advanced=False) -> Optional[Dict]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
            if not log_data:
                return None
            dynamic_features = self._advanced_dynamic_analysis(log_data) if advanced else log_data
            self.dynamic_features.append(dynamic_features)
            logger.info(f"Extracted dynamic features from {file_path}")
            return dynamic_features
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            logger.error(f"File error in {file_path}: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Error extracting dynamic features from {file_path}: {str(e)}")
            return None

    def _advanced_dynamic_analysis(self, log_data: Dict) -> Dict:
        return {
            "api_call_frequency": dict(Counter(log_data.get("api_calls", []))),
            "suspicious_network_patterns": self._detect_suspicious_network_patterns(log_data.get("network_traffic", {})),
            "runtime_behavior_score": self._calculate_runtime_behavior_score(log_data)
        }

    def _detect_suspicious_network_patterns(self, network_traffic: Dict) -> List[str]:
        return []

    def _calculate_runtime_behavior_score(self, log_data: Dict) -> float:
        return 0.0

    def extract_dynamic_features_from_ghidra(ghidra_output: str) -> Dict[str, List[str]]:
        # Initialize feature categories with empty lists
        feature_categories = {
            "API_System_Calls": [],
            "Process_Thread_Behavior": [],
            "Memory_Code_Injection": [],
            "Persistence_Mechanisms": [],
            "Network_Indicators": [],
            "Obfuscation_AntiAnalysis": [],
            "File_System_Behavior": [],
            "Command_Control_Patterns": [],
            "Malware_Config_Extraction": [],
            "Runtime_Behavior_Simulation": []
        }

        # Split Ghidra output into lines for easier analysis
        lines = ghidra_output.splitlines()
        for line in lines:
            line = line.lower()  # Convert to lowercase for uniformity

            # Check each category and append matching lines
            if any(api in line for api in ["createprocess", "regopenkeyex", "writefile", "execve", "mmap", "loadlibrary"]):
                feature_categories["API_System_Calls"].append(line)
            if any(call in line for call in ["createthread", "suspendthread", "openprocess", "shell32"]):
                feature_categories["Process_Thread_Behavior"].append(line)
            if any(term in line for term in ["virtualalloc", "heapalloc", "shellcode", "rop"]):
                feature_categories["Memory_Code_Injection"].append(line)
            if any(persist in line for persist in ["hkcu\\software", "run\\", "schtasks", "startup"]):
                feature_categories["Persistence_Mechanisms"].append(line)
            if any(net in line for net in ["http", "https", "socket", "connect", "dnsquery"]):
                feature_categories["Network_Indicators"].append(line)
            if any(obf in line for obf in ["isdebuggerpresent", "timingcheck", "packed", "hashing"]):
                feature_categories["Obfuscation_AntiAnalysis"].append(line)
            if any(fs in line for fs in ["createfile", "deletefile", "temp", "drop"]):
                feature_categories["File_System_Behavior"].append(line)
            if any(c2 in line for c2 in ["beacon", "irc", "post", "encode", "retry"]):
                feature_categories["Command_Control_Patterns"].append(line)
            if any(conf in line for conf in ["json", "xml", "config", "key:"]):
                feature_categories["Malware_Config_Extraction"].append(line)
            if any(runt in line for runt in ["getsysteminfo", "getusername", "switch", "dynamic"]):
                feature_categories["Runtime_Behavior_Simulation"].append(line)

        logger.info("Extracted Ghidra-derived dynamic features.")
        return feature_categories


    def add_behavioral_features(self, feature_dict: Dict) -> None:
        self.behavioral_features.append(feature_dict)
        logger.info("Behavioral features added")

    def transform_features(self, scaling_method=None, feature_selection=True) -> pd.DataFrame:
        try:
            combined_features = [
                {**static, **dynamic, **behavioral}
                for static, dynamic, behavioral in zip(self.static_features, self.dynamic_features, self.behavioral_features)
            ]
            df = pd.DataFrame(combined_features)
            self.handle_missing_data(df)
            scaler = self.scaling_methods.get(scaling_method or "standard", StandardScaler())
            scaled = scaler.fit_transform(df)
            if feature_selection:
                scaled = self.feature_selector.fit_transform(scaled, np.zeros(len(scaled)))
            return pd.DataFrame(scaled, columns=[f"feature_{i}" for i in range(scaled.shape[1])])
        except Exception as e:
            logger.error(f"Feature transformation error: {e}")
            raise

    def handle_missing_data(self, df: pd.DataFrame, strategy="mean") -> None:
        try:
            if strategy == "mean":
                df.fillna(df.mean(numeric_only=True), inplace=True)
            elif strategy == "median":
                df.fillna(df.median(numeric_only=True), inplace=True)
            elif strategy == "drop":
                df.dropna(inplace=True)
            logger.info(f"Handled missing data using {strategy} strategy")
        except Exception as e:
            logger.error(f"Error handling missing data: {e}")

    def balance_classes(self, df: pd.DataFrame, labels: np.ndarray, method="upsample") -> Tuple[pd.DataFrame, np.ndarray]:
        try:
            df["label"] = labels
            df_majority = df[df.label == 0]
            df_minority = df[df.label == 1]
            if method == "upsample":
                df_minority = resample(df_minority, replace=True, n_samples=len(df_majority), random_state=42)
                df_balanced = pd.concat([df_majority, df_minority])
            elif method == "downsample":
                df_majority = resample(df_majority, replace=False, n_samples=len(df_minority), random_state=42)
                df_balanced = pd.concat([df_majority, df_minority])
            else:
                logger.warning("Invalid method specified, returning original dataset")
                return df.drop(columns="label"), labels
            df_balanced = df_balanced.sample(frac=1).reset_index(drop=True)
            return df_balanced.drop(columns="label"), df_balanced["label"].to_numpy()
        except Exception as e:
            logger.error(f"Class balancing error: {e}")
            raise

    def generate_dna(self, features: Dict[str, Any]) -> str:
        feature_str = json.dumps(features, sort_keys=True)
        return hashlib.sha256(feature_str.encode()).hexdigest()

