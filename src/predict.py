import os
import sys

import joblib

from config import MODEL_PATH, setup_logging
from pipeline import analyze_url, format_cli_report

setup_logging()


def load_model():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = MODEL_PATH if os.path.isabs(MODEL_PATH) else os.path.join(base_dir, "..", "models", "phishing_model.pkl")
    return joblib.load(model_path)


def main():
    print("GuardianAI - Advanced Threat Detection Engine")
    print("-" * 48)

    try:
        model = load_model()
    except FileNotFoundError:
        print("Error: phishing model not found. Run train.py first.")
        sys.exit(1)

    while True:
        url = input("\nEnter URL to check (or type 'exit'): ").strip()

        if url.lower() == "exit":
            print("Exiting GuardianAI. Stay safe online.")
            break

        if not url:
            continue

        try:
            analysis = analyze_url(url, model)
            print(format_cli_report(analysis))
        except Exception as exc:
            print(f"\nAnalysis failed: {exc}")


if __name__ == "__main__":
    main()
