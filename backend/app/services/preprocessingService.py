import os
import json
import logging
import argparse
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Union
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.decomposition import TruncatedSVD

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class PreprocessingService:
    """
    Service to preprocess malware data for analysis and machine learning.
    """
    def __init__(self):
        """
        Initialize preprocessing service with default configurations.
        """
        self.numeric_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='mean')),
            ('scaler', StandardScaler())
        ])
        self.categorical_transformer = Pipeline(steps=[
            ('imputer', SimpleImputer(strategy='constant', fill_value='missing')),
            ('onehot', OneHotEncoder(handle_unknown='ignore'))
        ])
        self.text_transformer = Pipeline(steps=[
            ('tfidf', TfidfVectorizer(max_features=500)),
            ('svd', TruncatedSVD(n_components=50))
        ])
        self.preprocessor = None

    def preprocess_malware_data(self, data: Union[Dict, pd.DataFrame]) -> pd.DataFrame:
        """
        Preprocess raw malware data into a clean, structured format.

        Args:
            data (Union[Dict, pd.DataFrame]): Raw malware data

        Returns:
            pd.DataFrame: Preprocessed data ready for analysis
        """
        try:
            # Convert dictionary to DataFrame if necessary
            if isinstance(data, dict):
                data = pd.DataFrame([data])
            elif not isinstance(data, pd.DataFrame):
                raise ValueError("Input data must be a dictionary or pandas DataFrame")

            # Define column types
            numeric_features = [
                col for col in data.columns 
                if pd.api.types.is_numeric_dtype(data[col])
            ]
            categorical_features = [
                col for col in data.columns 
                if pd.api.types.is_string_dtype(data[col]) and col != "text_data"
            ]
            text_features = ["text_data"] if "text_data" in data.columns else []

            # Build preprocessing pipeline
            transformers = []
            if numeric_features:
                transformers.append(('numeric', self.numeric_transformer, numeric_features))
            if categorical_features:
                transformers.append(('categorical', self.categorical_transformer, categorical_features))
            if text_features:
                transformers.append(('text', self.text_transformer, text_features))

            self.preprocessor = ColumnTransformer(transformers=transformers)

            # Apply preprocessing
            preprocessed_data = self.preprocessor.fit_transform(data)

            # Convert back to DataFrame
            feature_names = self._get_feature_names()
            preprocessed_df = pd.DataFrame(preprocessed_data, columns=feature_names)

            logger.info("Malware data preprocessing completed successfully")
            return preprocessed_df
        except Exception as e:
            logger.error(f"Malware data preprocessing failed: {e}")
            raise

    def _get_feature_names(self) -> List[str]:
        """
        Retrieve feature names after preprocessing.

        Returns:
            List[str]: List of feature names
        """
        feature_names = []
        for name, transformer, columns in self.preprocessor.transformers_:
            if hasattr(transformer, 'get_feature_names_out'):
                feature_names.extend(transformer.get_feature_names_out(columns))
            else:
                feature_names.extend(columns)
        return feature_names

    @staticmethod
    def save_preprocessed_data(data: pd.DataFrame, output_dir: str = "preprocessed_data") -> str:
        """
        Save preprocessed data to a file.

        Args:
            data (pd.DataFrame): Preprocessed data
            output_dir (str): Directory to save the data

        Returns:
            str: Path to the saved file
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = os.path.join(output_dir, f"preprocessed_data_{timestamp}.json")
            data.to_json(output_path, orient="records", lines=True)
            logger.info(f"Preprocessed data saved to {output_path}")
            return output_path
        except Exception as e:
            logger.error(f"Failed to save preprocessed data: {e}")
            raise

    @staticmethod
    def load_preprocessed_data(file_path: str) -> pd.DataFrame:
        """
        Load preprocessed data from a file.

        Args:
            file_path (str): Path to the preprocessed data file

        Returns:
            pd.DataFrame: Loaded preprocessed data
        """
        try:
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"File not found: {file_path}")
            data = pd.read_json(file_path, orient="records", lines=True)
            logger.info(f"Preprocessed data loaded from {file_path}")
            return data
        except Exception as e:
            logger.error(f"Failed to load preprocessed data: {e}")
            raise


# --------------------------- CLI HANDLER --------------------------- #

def cli_preprocess(args):
    """CLI command for preprocessing malware data."""
    preprocessing_service = PreprocessingService()
    
    with open(args.input, "r") as file:
        raw_data = json.load(file)

    preprocessed_data = preprocessing_service.preprocess_malware_data(raw_data)
    output_path = preprocessing_service.save_preprocessed_data(preprocessed_data, args.output)
    
    print(f"Preprocessed data saved at: {output_path}")


def cli_save(args):
    """CLI command for saving preprocessed data."""
    preprocessing_service = PreprocessingService()
    df = preprocessing_service.preprocess_malware_data({})  # Empty for testing

    output_path = preprocessing_service.save_preprocessed_data(df, args.output)
    print(f"Preprocessed data saved at: {output_path}")


def cli_load(args):
    """CLI command for loading preprocessed data."""
    preprocessing_service = PreprocessingService()
    df = preprocessing_service.load_preprocessed_data(args.file)
    
    print(df.head())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Malware Data Preprocessing CLI")
    subparsers = parser.add_subparsers(help="Commands")

    parser_preprocess = subparsers.add_parser("preprocess", help="Preprocess malware data")
    parser_preprocess.add_argument("--input", required=True, help="Path to raw malware data (.json)")
    parser_preprocess.add_argument("--output", default="preprocessed_data", help="Directory to save preprocessed data")
    parser_preprocess.set_defaults(func=cli_preprocess)

    parser_save = subparsers.add_parser("save", help="Save preprocessed data")
    parser_save.add_argument("--output", default="preprocessed_data", help="Directory to save preprocessed data")
    parser_save.set_defaults(func=cli_save)

    parser_load = subparsers.add_parser("load", help="Load preprocessed data")
    parser_load.add_argument("--file", required=True, help="Path to preprocessed data file")
    parser_load.set_defaults(func=cli_load)

    args = parser.parse_args()
    args.func(args)

