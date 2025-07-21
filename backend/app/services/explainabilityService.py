import os
import json
import logging
import argparse
import pickle
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from sklearn.inspection import permutation_importance
from sklearn.tree import export_text
from lime import lime_tabular
import shap
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class ExplainabilityService:
    def __init__(self):
        """Initialize explainability service."""
        try:
            logger.info("Explainability service initialized successfully")
        except Exception as e:
            logger.error(f"Explainability service initialization failed: {e}")
            raise

    @staticmethod
    def generate_feature_importance(model: Any, X_train: pd.DataFrame, y_train: pd.Series) -> Dict[str, float]:
        """Compute feature importance using permutation importance."""
        try:
            perm_importance = permutation_importance(model, X_train, y_train, n_repeats=10, random_state=42)
            feature_importance = {
                feature: perm_importance.importances_mean[i]
                for i, feature in enumerate(X_train.columns)
            }
            logger.info("Feature importance generated successfully")
            return feature_importance
        except Exception as e:
            logger.error(f"Feature importance generation failed: {e}")
            raise

    @staticmethod
    def generate_lime_explanation(model: Any, X_train: pd.DataFrame, X_test: pd.DataFrame, instance_index: int) -> Dict[str, Any]:
        """Generate LIME explanation for a specific instance."""
        try:
            explainer = lime_tabular.LimeTabularExplainer(
                training_data=np.array(X_train),
                feature_names=X_train.columns,
                class_names=["Benign", "Malicious"],
                mode="classification"
            )
            instance = X_test.iloc[instance_index]
            explanation = explainer.explain_instance(instance.values, model.predict_proba)
            explanation_details = {
                "as_list": explanation.as_list(),
                "as_map": explanation.as_map(),
                "visual_html": explanation.as_html()
            }
            logger.info("LIME explanation generated successfully")
            return explanation_details
        except Exception as e:
            logger.error(f"LIME explanation generation failed: {e}")
            raise

    @staticmethod
    def generate_shap_explanation(model: Any, X_train: pd.DataFrame, X_test: pd.DataFrame) -> Dict[str, Any]:
        """Generate SHAP explanations for test dataset."""
        try:
            explainer = shap.Explainer(model, X_train)
            shap_values = explainer(X_test)
            mean_shap_values = np.abs(shap_values.values).mean(axis=0)
            feature_importance = {
                feature: mean_shap_values[i]
                for i, feature in enumerate(X_train.columns)
            }
            logger.info("SHAP explanation generated successfully")
            return {"mean_shap_values": feature_importance}
        except Exception as e:
            logger.error(f"SHAP explanation generation failed: {e}")
            raise

    @staticmethod
    def generate_decision_tree_rules(model: Any, feature_names: List[str]) -> str:
        """Extract decision tree rules in human-readable format."""
        try:
            tree_rules = export_text(model, feature_names=feature_names)
            logger.info("Decision tree rules generated successfully")
            return tree_rules
        except Exception as e:
            logger.error(f"Decision tree rule generation failed: {e}")
            raise


# ---------------------------- CLI HANDLER ---------------------------- #

def cli_feature_importance(args):
    """CLI command for feature importance computation."""
    model = pickle.load(open(args.model, "rb"))
    data = pd.read_csv(args.data)
    X_train = data.drop(columns=["label"])
    y_train = data["label"]
    importance = ExplainabilityService.generate_feature_importance(model, X_train, y_train)
    print(json.dumps(importance, indent=4))


def cli_lime_explain(args):
    """CLI command for generating LIME explanations."""
    model = pickle.load(open(args.model, "rb"))
    train_data = pd.read_csv(args.train)
    test_data = pd.read_csv(args.test)
    X_train = train_data.drop(columns=["label"])
    X_test = test_data.drop(columns=["label"])
    explanation = ExplainabilityService.generate_lime_explanation(model, X_train, X_test, args.index)
    print(json.dumps(explanation, indent=4))


def cli_shap_explain(args):
    """CLI command for generating SHAP explanations."""
    model = pickle.load(open(args.model, "rb"))
    train_data = pd.read_csv(args.train)
    test_data = pd.read_csv(args.test)
    X_train = train_data.drop(columns=["label"])
    X_test = test_data.drop(columns=["label"])
    explanation = ExplainabilityService.generate_shap_explanation(model, X_train, X_test)
    print(json.dumps(explanation, indent=4))


def cli_tree_rules(args):
    """CLI command for extracting decision tree rules."""
    model = pickle.load(open(args.model, "rb"))
    with open(args.features, "r") as f:
        feature_names = json.load(f)
    rules = ExplainabilityService.generate_decision_tree_rules(model, feature_names)
    print(rules)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Explainability Service CLI")
    subparsers = parser.add_subparsers(help="Commands")

    parser_feature = subparsers.add_parser("feature_importance", help="Compute feature importance")
    parser_feature.add_argument("--model", required=True, help="Path to trained model (.pkl)")
    parser_feature.add_argument("--data", required=True, help="Path to training data (.csv)")
    parser_feature.set_defaults(func=cli_feature_importance)

    parser_lime = subparsers.add_parser("lime_explain", help="Generate LIME explanations")
    parser_lime.add_argument("--model", required=True, help="Path to trained model (.pkl)")
    parser_lime.add_argument("--train", required=True, help="Path to training data (.csv)")
    parser_lime.add_argument("--test", required=True, help="Path to test data (.csv)")
    parser_lime.add_argument("--index", type=int, required=True, help="Index of instance to explain")
    parser_lime.set_defaults(func=cli_lime_explain)

    parser_shap = subparsers.add_parser("shap_explain", help="Generate SHAP explanations")
    parser_shap.add_argument("--model", required=True, help="Path to trained model (.pkl)")
    parser_shap.add_argument("--train", required=True, help="Path to training data (.csv)")
    parser_shap.add_argument("--test", required=True, help="Path to test data (.csv)")
    parser_shap.set_defaults(func=cli_shap_explain)

    parser_tree = subparsers.add_parser("tree_rules", help="Extract decision tree rules")
    parser_tree.add_argument("--model", required=True, help="Path to trained model (.pkl)")
    parser_tree.add_argument("--features", required=True, help="Path to feature names (.json)")
    parser_tree.set_defaults(func=cli_tree_rules)

    args = parser.parse_args()
    args.func(args)

