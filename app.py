import joblib
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for

from database import (
    add_scan,
    get_daily_scan_stats,
    get_dashboard_stats,
    get_recent_scans,
    get_scan_by_id,
    get_scans_filtered,
    init_db,
)
from feature_extractor import build_feature_frame, extract_features
from report_generator import generate_history_pdf, generate_pdf_report

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model.pkl"

app = Flask(__name__)
app.secret_key = "phishing-demo-secret"

init_db()


def load_model():
    """Load the trained model from disk or train it if it does not exist yet."""
    if not MODEL_PATH.exists():
        subprocess.run([sys.executable, str(BASE_DIR / "train_model.py")], check=True)

    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["feature_names"], bundle.get("accuracy", 0.0)


def determine_risk_level(feature_dict, prediction, confidence):
    """Map prediction confidence and URL signals to a consistent risk level."""
    suspicious_count = 0
    suspicious_count += 1 if feature_dict["has_at"] else 0
    suspicious_count += 1 if feature_dict["has_dash"] else 0
    suspicious_count += 1 if feature_dict["has_ip"] else 0
    suspicious_count += 1 if feature_dict["has_https"] == 0 else 0
    suspicious_count += 1 if feature_dict["subdomains"] >= 2 else 0
    suspicious_count += 1 if feature_dict["dots"] >= 4 else 0
    suspicious_count += 1 if feature_dict["url_length"] > 40 else 0

    if prediction == "Legitimate":
        if confidence >= 80 and suspicious_count <= 2:
            return "Low Risk"
        return "Medium Risk"

    if prediction == "Phishing":
        if confidence >= 70 and suspicious_count >= 2:
            return "High Risk"
        return "Medium Risk"

    return "Medium Risk"


def get_feature_status(feature_dict):
    """Build status metadata for each extracted feature."""
    def safe(value, threshold, warn_threshold=None):
        if value <= threshold:
            return "safe"
        if warn_threshold is not None and value <= warn_threshold:
            return "warning"
        return "danger"

    return {
        "URL Length": {
            "value": f"{feature_dict['url_length']} characters",
            "status": safe(feature_dict["url_length"], 40, 60),
            "label": "Normal" if feature_dict["url_length"] <= 40 else "Long" if feature_dict["url_length"] <= 60 else "Very long",
        },
        "HTTPS Availability": {
            "value": "Secure HTTPS used" if feature_dict["has_https"] == 1 else "No HTTPS detected",
            "status": "safe" if feature_dict["has_https"] == 1 else "danger",
            "label": "Secure" if feature_dict["has_https"] == 1 else "Insecure",
        },
        "Number of Dots": {
            "value": f"{feature_dict['dots']} dots",
            "status": safe(feature_dict["dots"], 3, 4),
            "label": "Normal" if feature_dict["dots"] <= 3 else "High" if feature_dict["dots"] <= 4 else "Excessive",
        },
        "@ Symbol": {
            "value": "No @ symbol found" if feature_dict["has_at"] == 0 else "@ symbol detected",
            "status": "safe" if feature_dict["has_at"] == 0 else "danger",
            "label": "Absent" if feature_dict["has_at"] == 0 else "Present",
        },
        "Hyphen (-)": {
            "value": "No hyphen found" if feature_dict["has_dash"] == 0 else "Hyphen detected",
            "status": "safe" if feature_dict["has_dash"] == 0 else "warning",
            "label": "Absent" if feature_dict["has_dash"] == 0 else "Present",
        },
        "Number of Subdomains": {
            "value": f"{feature_dict['subdomains']} subdomain(s)",
            "status": safe(feature_dict["subdomains"], 1, 2),
            "label": "Low" if feature_dict["subdomains"] <= 1 else "Moderate" if feature_dict["subdomains"] <= 2 else "High",
        },
        "IP Address in URL": {
            "value": "No IP address in URL" if feature_dict["has_ip"] == 0 else "IP address detected",
            "status": "safe" if feature_dict["has_ip"] == 0 else "danger",
            "label": "Absent" if feature_dict["has_ip"] == 0 else "Present",
        },
    }


def build_reason_list(feature_dict, prediction):
    """Create dynamic detection reasons that match the current prediction state."""
    reasons = []

    if prediction == "Legitimate":
        if feature_dict["has_https"] == 1:
            reasons.append("HTTPS is enabled.")
        else:
            reasons.append("HTTPS is not enabled.")

        if feature_dict["has_ip"] == 0:
            reasons.append("No IP address detected.")
        else:
            reasons.append("IP address detected.")

        if feature_dict["has_at"] == 0:
            reasons.append("No '@' symbol found.")
        else:
            reasons.append("'@' symbol found.")

        if feature_dict["has_dash"] == 0 and feature_dict["subdomains"] <= 1 and feature_dict["dots"] <= 3 and feature_dict["url_length"] <= 40:
            reasons.append("Safe URL structure.")
        else:
            reasons.append("Some URL structure elements look slightly unusual.")

        reasons.append("Model predicts this URL as legitimate.")
    else:
        reasons.append("Suspicious URL pattern detected.")
        reasons.append("Unsafe keywords or URL structure found.")
        reasons.append("High phishing probability.")
        reasons.append("Model predicts this URL as phishing.")

    return reasons


def build_result_payload(prediction, confidence, feature_dict):
    """Create a visual payload for the prediction card and feature list."""
    risk_level = determine_risk_level(feature_dict, prediction, confidence)
    feature_analysis = get_feature_status(feature_dict)
    reasons = build_reason_list(feature_dict, prediction)

    if risk_level == "High Risk":
        card_class = "prediction-card danger"
        badge_class = "badge bg-danger"
        progress_class = "bg-danger"
        icon_class = "fa-solid fa-shield-halved text-danger"
        status_text = "High-risk phishing pattern detected"
        status_text_class = "text-danger"
        explanation = "This URL shows several suspicious indicators and is likely to be phishing."
        panel_title = "High Risk Alert"
    elif risk_level == "Medium Risk":
        card_class = "prediction-card warning"
        badge_class = "badge bg-warning text-dark"
        progress_class = "bg-warning"
        icon_class = "fa-solid fa-triangle-exclamation text-warning"
        status_text = "Suspicious pattern detected"
        status_text_class = "text-warning"
        explanation = "This URL looks suspicious and should be reviewed carefully."
        panel_title = "Medium Risk"
    else:
        card_class = "prediction-card success"
        badge_class = "badge bg-success"
        progress_class = "bg-success"
        icon_class = "fa-solid fa-shield-halved text-success"
        status_text = "Legitimate URL confirmed"
        status_text_class = "text-success"
        explanation = "This URL appears legitimate based on the trained machine learning model."
        panel_title = "Low Risk"

    return {
        "prediction": prediction,
        "confidence": round(confidence, 2),
        "risk_level": risk_level,
        "explanation": explanation,
        "panel_title": panel_title,
        "card_class": card_class,
        "badge_class": badge_class,
        "progress_class": progress_class,
        "icon_class": icon_class,
        "status_text": status_text,
        "status_text_class": status_text_class,
        "feature_analysis": feature_analysis,
        "reasons": reasons,
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.route("/", methods=["GET", "POST"])
def index():
    """Render the scan page and process incoming URL submissions."""
    model, feature_names, accuracy = load_model()
    history = get_recent_scans(6)
    result = None
    submitted_url = ""

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        if not submitted_url:
            flash("Please enter a URL to analyze.", "warning")
            return redirect(url_for("index"))

        try:
            feature_dict, normalized_url = extract_features(submitted_url)
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("index"))

        feature_frame = build_feature_frame(feature_dict)
        feature_frame = feature_frame[feature_names]

        prediction_code = model.predict(feature_frame)[0]
        prediction = "Phishing" if prediction_code == 1 else "Legitimate"
        confidence = float(max(model.predict_proba(feature_frame)[0]) * 100)
        result = build_result_payload(prediction, confidence, feature_dict)

        add_scan(normalized_url, result["prediction"], result["confidence"], result["risk_level"], result["feature_analysis"])
        history = get_recent_scans(6)
        flash("Scan completed successfully.", "success")

    return render_template("index.html", result=result, submitted_url=submitted_url, history=history, accuracy=accuracy)


@app.route("/dashboard")
def dashboard():
    """Show dashboard statistics, recent activity, and charts."""
    _, _, accuracy = load_model()
    stats = get_dashboard_stats()
    stats["accuracy"] = accuracy
    stats["daily_scans"] = get_daily_scan_stats()
    history = get_recent_scans(10)
    return render_template("dashboard.html", stats=stats, history=history)


@app.route("/history")
def history():
    """Show the complete scan history with filtering and search options."""
    search = request.args.get("search", "").strip()
    prediction_filter = request.args.get("prediction", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    history = get_scans_filtered(search, prediction_filter, risk_filter, start_date, end_date)
    return render_template(
        "history.html",
        history=history,
        search=search,
        prediction_filter=prediction_filter,
        risk_filter=risk_filter,
        start_date=start_date,
        end_date=end_date,
    )


@app.route("/download_report/<int:scan_id>")
def download_report(scan_id):
    """Generate and download a PDF report for a saved scan."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        flash("The requested report was not found.", "danger")
        return redirect(url_for("history"))

    pdf_buffer = generate_pdf_report(scan)
    return send_file(pdf_buffer, download_name=f"report_{scan_id}.pdf", as_attachment=True, mimetype="application/pdf")


@app.route("/export_history_pdf")
def export_history_pdf():
    """Export the current filtered history to a PDF file."""
    search = request.args.get("search", "").strip()
    prediction_filter = request.args.get("prediction", "").strip()
    risk_filter = request.args.get("risk", "").strip()
    start_date = request.args.get("start_date", "").strip()
    end_date = request.args.get("end_date", "").strip()

    history = get_scans_filtered(search, prediction_filter, risk_filter, start_date, end_date)
    pdf_buffer = generate_history_pdf(history)
    return send_file(pdf_buffer, download_name="scan_history.pdf", as_attachment=True, mimetype="application/pdf")


if __name__ == "__main__":
    app.run(debug=True)
