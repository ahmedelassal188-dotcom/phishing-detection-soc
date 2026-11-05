from fastapi import Depends
from app.auth import require_soc_login
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
import re
from app.report_generator import generate_incident_report
from app.siem_alerts import write_siem_alert
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
from tempfile import TemporaryDirectory

from fastapi import FastAPI, UploadFile, File, HTTPException

from app.analysis_engine import analyze_message


app = FastAPI(
    title="Phishing Detection & Analysis System",
    description="SOC Blue Team Email Analysis Platform",
    version="0.2.0"
)


@app.get("/")
def home():
    return {
        "application": "Phishing Detection System",
        "status": "Running",
        "version": "0.2.0"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze", dependencies=[Depends(require_soc_login)])
def analyze_uploaded_email(file: UploadFile = File(...)):

    if not (file.filename or "").lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are accepted"
        )

    max_size = 5 * 1024 * 1024
    total_size = 0

    with TemporaryDirectory() as folder:
        email_path = Path(folder) / "uploaded_email.eml"

        with open(email_path, "wb") as output:
            while True:
                chunk = file.file.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > max_size:
                    raise HTTPException(
                        status_code=413,
                        detail="File exceeds 5 MB limit"
                    )

                output.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Empty email file"
            )
# Validate email structure before analysis
        parsed_email = BytesParser(
            policy=policy.default
        ).parsebytes(email_path.read_bytes())

        sender_header = parsed_email.get("From", "")
        sender_address = parseaddr(str(sender_header))[1]

        if (
            not sender_address
            or "@" not in sender_address
            or sender_address.startswith("@")
            or sender_address.endswith("@")
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid EML: missing or malformed From header"
            )

        try:
            result = analyze_message(str(email_path))

            # Automatically log suspicious emails for Wazuh
            alert = write_siem_alert(result)

            result["siem_alert_generated"] = alert is not None
            report_path = generate_incident_report(result)
            result["report_filename"] = Path(report_path).name

            return result

        except ValueError as error:
            raise HTTPException(
                status_code=422,
                detail=str(error)
            ) from error
# Dashboard configuration
BASE_DIR = Path(__file__).resolve().parent

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static"
)


@app.get("/dashboard", dependencies=[Depends(require_soc_login)])
def dashboard():
    return FileResponse(
        BASE_DIR / "templates" / "index.html"
    )
@app.get(
    "/reports/{filename}",
    include_in_schema=False,
    dependencies=[Depends(require_soc_login)]
)
def download_incident_report(filename: str):
    if not re.fullmatch(r"INC-[0-9A-F]{10}\.pdf", filename):
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    report_path = (
        Path(__file__).resolve().parent.parent
        / "reports"
        / filename
    )

    if not report_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Report not found"
        )

    return FileResponse(
        path=report_path,
        filename=filename,
        media_type="application/pdf"
    )
