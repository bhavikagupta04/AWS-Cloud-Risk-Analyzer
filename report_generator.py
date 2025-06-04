from reportlab.pdfgen import canvas
from security_analyzer import run_all_checks

def create_pdf_report(filename="reports/security_report.pdf"):
    findings = run_all_checks()
    c = canvas.Canvas(filename)
    c.setFont("Helvetica", 12)
    c.drawString(50, 800, "AWS Security Findings Report")
    y = 780
    for line in findings:
        c.drawString(50, y, f"- {line}")
        y -= 15
        if y < 50:
            c.showPage()
            y = 800
    c.save()

if __name__ == "__main__":
    create_pdf_report()
