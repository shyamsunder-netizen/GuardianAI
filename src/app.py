from flask import Flask, render_template, request
import joblib
import os

from config import MODEL_PATH, setup_logging
from pipeline import analyze_url, format_web_result

setup_logging()

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = MODEL_PATH if os.path.isabs(MODEL_PATH) else os.path.join(BASE_DIR, "..", "models", "phishing_model.pkl")

model = joblib.load(model_path)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        try:
            url = request.form["url"]
            analysis = analyze_url(url, model)
            result = format_web_result(analysis)

        except Exception as e:
            result = {
                "url": url if "url" in locals() else "Unknown",
                "score": 0,
                "risk": "ERROR",
                "confidence": 0,
                "reasons": [str(e)],
                "explanation": {},
            }

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
