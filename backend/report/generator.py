"""PDF report generator using Jinja2 templates and WeasyPrint.

Placeholder implementation. The production version will:
1. Load the HTML template from report/templates/.
2. Render scan data and findings into the template.
3. Convert the rendered HTML to PDF via WeasyPrint.
4. Upload the PDF to cloud storage and return the download URL.
"""

import logging
from pathlib import Path
from uuid import UUID

from jinja2 import Environment, FileSystemLoader

logger = logging.getLogger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"


def _get_jinja_env() -> Environment:
    """Create a Jinja2 environment pointed at the templates directory."""
    return Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )


def render_report_html(
    scan_data: dict,
    findings: list[dict],
) -> str:
    """Render the scan report as an HTML string.

    Falls back to a minimal inline template when no template file
    exists yet.
    """
    env = _get_jinja_env()

    try:
        template = env.get_template("report.html")
    except Exception:
        logger.warning("Template not found; using inline fallback")
        template = env.from_string(
            "<html><body>"
            "<h1>RepolyzeAI Report</h1>"
            "<p>Scan: {{ scan.repo_name }}</p>"
            "<p>Findings: {{ findings | length }}</p>"
            "</body></html>"
        )

    return template.render(scan=scan_data, findings=findings)


def generate_pdf(
    scan_id: UUID,
    scan_data: dict,
    findings: list[dict],
) -> bytes:
    """Generate a PDF report and return raw bytes.

    Placeholder: returns empty bytes until WeasyPrint integration is
    wired up.
    """
    html = render_report_html(scan_data, findings)
    logger.info("Generated HTML report for scan %s (%d chars)", scan_id, len(html))

    # TODO: Convert HTML to PDF with WeasyPrint:
    # from weasyprint import HTML
    # return HTML(string=html).write_pdf()

    return html.encode("utf-8")
