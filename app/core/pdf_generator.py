import io
from xhtml2pdf import pisa
from jinja2 import Environment, FileSystemLoader

class IncidentPDFGenerator:
    def __init__(self, templates_dir: str = "app/templates"):
        self.env = Environment(loader=FileSystemLoader(templates_dir))

    def generate(self, data: dict) -> bytes:
        template = self.env.get_template("report_pdf.html")
        html_content = template.render(data=data)
        
        pdf_stream = io.BytesIO()
        pisa.CreatePDF(io.StringIO(html_content), dest=pdf_stream)
        return pdf_stream.getvalue()
