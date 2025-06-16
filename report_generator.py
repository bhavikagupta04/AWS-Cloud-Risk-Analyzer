from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import os
from datetime import datetime
from security_analyzer import get_detailed_findings, get_summary_stats


def create_pdf_report(filename="reports/security_report.pdf"):
    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)

    # Get data
    detailed_findings = get_detailed_findings()
    stats = get_summary_stats()

    # Create PDF document
    doc = SimpleDocTemplate(filename, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#2c3e50'),
        spaceAfter=30,
        alignment=TA_CENTER
    )

    subtitle_style = ParagraphStyle(
        'CustomSubtitle',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#7f8c8d'),
        spaceAfter=20,
        alignment=TA_CENTER
    )

    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#34495e'),
        spaceAfter=12,
        spaceBefore=20
    )

    # Title Page
    story.append(Spacer(1, 2 * inch))
    story.append(Paragraph("AWS Cloud Risk Analyzer", title_style))
    story.append(Paragraph("Security Assessment Report", subtitle_style))
    story.append(Paragraph("by Bhavika Gupta", subtitle_style))
    story.append(Spacer(1, 1 * inch))

    # Report metadata
    report_info = [
        ['Report Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ['Total Issues Found:', str(stats['total_issues'])],
        ['Services Scanned:', str(stats['services_affected'])],
        ['Scan Status:', 'Complete']
    ]

    info_table = Table(report_info, colWidths=[2 * inch, 3 * inch])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))

    story.append(info_table)
    story.append(PageBreak())

    # Executive Summary
    story.append(Paragraph("Executive Summary", heading_style))

    summary_text = f"""
    This security assessment identified <b>{stats['total_issues']} security issues</b> across your AWS environment. 
    The analysis covered {stats['services_affected']} different AWS services including IAM, S3, EC2, and RDS.

    <b>Risk Breakdown:</b><br/>
    • Critical Issues: {stats['critical_issues']} (require immediate attention)<br/>
    • High Priority Issues: {stats['high_issues']} (should be addressed within 1 week)<br/>
    • Medium Priority Issues: {stats['medium_issues']} (should be addressed within 1 month)<br/>

    The most common security issues found were related to overly permissive access controls, 
    missing multi-factor authentication, and publicly accessible resources.
    """

    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 0.5 * inch))

    # Risk Distribution Chart
    if stats['total_issues'] > 0:
        story.append(Paragraph("Risk Distribution", heading_style))

        # Create pie chart
        drawing = Drawing(400, 200)
        pie = Pie()
        pie.x = 50
        pie.y = 50
        pie.width = 100
        pie.height = 100
        pie.data = [stats['critical_issues'], stats['high_issues'], stats['medium_issues']]
        pie.labels = ['Critical', 'High', 'Medium']
        pie.slices.strokeWidth = 0.5
        pie.slices[0].fillColor = colors.HexColor('#e74c3c')
        pie.slices[1].fillColor = colors.HexColor('#f39c12')
        pie.slices[2].fillColor = colors.HexColor('#27ae60')

        drawing.add(pie)
        story.append(drawing)
        story.append(Spacer(1, 0.3 * inch))

    # Service Breakdown
    service_counts = {}
    for finding in detailed_findings:
        service = finding['service']
        service_counts[service] = service_counts.get(service, 0) + 1

    if service_counts:
        story.append(Paragraph("Issues by Service", heading_style))

        service_data = [['AWS Service', 'Number of Issues', 'Percentage']]
        for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
            percentage = f"{(count / stats['total_issues'] * 100):.1f}%"
            service_data.append([service, str(count), percentage])

        service_table = Table(service_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        service_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))

        story.append(service_table)
        story.append(Spacer(1, 0.3 * inch))

    # Detailed Findings
    story.append(PageBreak())
    story.append(Paragraph("Detailed Security Findings", heading_style))

    if detailed_findings:
        # Group findings by severity
        critical_findings = [f for f in detailed_findings if f['severity'] == 'Critical']
        high_findings = [f for f in detailed_findings if f['severity'] == 'High']
        medium_findings = [f for f in detailed_findings if f['severity'] == 'Medium']

        # Critical Issues
        if critical_findings:
            story.append(Paragraph("🔴 Critical Issues", ParagraphStyle(
                'CriticalHeader', parent=styles['Heading3'],
                textColor=colors.HexColor('#e74c3c'), fontSize=14
            )))

            for i, finding in enumerate(critical_findings, 1):
                issue_text = f"""
                <b>{i}. {finding['issue_type']} - {finding['service']}</b><br/>
                <b>Resource:</b> {finding['resource']}<br/>
                <b>Description:</b> {finding['description']}<br/>
                <b>Recommendation:</b> {finding['recommendation']}<br/>
                """
                story.append(Paragraph(issue_text, styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))

        # High Issues
        if high_findings:
            story.append(Paragraph("🟡 High Priority Issues", ParagraphStyle(
                'HighHeader', parent=styles['Heading3'],
                textColor=colors.HexColor('#f39c12'), fontSize=14
            )))

            for i, finding in enumerate(high_findings, 1):
                issue_text = f"""
                <b>{i}. {finding['issue_type']} - {finding['service']}</b><br/>
                <b>Resource:</b> {finding['resource']}<br/>
                <b>Description:</b> {finding['description']}<br/>
                <b>Recommendation:</b> {finding['recommendation']}<br/>
                """
                story.append(Paragraph(issue_text, styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))

        # Medium Issues
        if medium_findings:
            story.append(Paragraph("🟢 Medium Priority Issues", ParagraphStyle(
                'MediumHeader', parent=styles['Heading3'],
                textColor=colors.HexColor('#27ae60'), fontSize=14
            )))

            for i, finding in enumerate(medium_findings, 1):
                issue_text = f"""
                <b>{i}. {finding['issue_type']} - {finding['service']}</b><br/>
                <b>Resource:</b> {finding['resource']}<br/>
                <b>Description:</b> {finding['description']}<br/>
                <b>Recommendation:</b> {finding['recommendation']}<br/>
                """
                story.append(Paragraph(issue_text, styles['Normal']))
                story.append(Spacer(1, 0.2 * inch))

    else:
        story.append(Paragraph("No security issues found! Your AWS environment appears to be well-configured.",
                               styles['Normal']))

    # Recommendations Summary
    story.append(PageBreak())
    story.append(Paragraph("Next Steps & Recommendations", heading_style))

    recommendations_text = """
    <b>Immediate Actions (Critical Issues):</b><br/>
    1. Review and restrict any publicly accessible S3 buckets<br/>
    2. Disable public access for RDS instances<br/>
    3. Stop using root account for daily operations<br/>

    <b>Short-term Actions (High Priority):</b><br/>
    1. Enable MFA for all IAM users<br/>
    2. Review and tighten security group rules<br/>
    3. Implement least privilege access policies<br/>

    <b>Long-term Actions (Medium Priority):</b><br/>
    1. Regular access key rotation and cleanup<br/>
    2. Implement automated security monitoring<br/>
    3. Regular security assessments and audits<br/>

    <b>Best Practices:</b><br/>
    • Use IAM roles instead of access keys where possible<br/>
    • Enable CloudTrail for audit logging<br/>
    • Implement AWS Config for compliance monitoring<br/>
    • Use AWS Security Hub for centralized security findings<br/>
    """

    story.append(Paragraph(recommendations_text, styles['Normal']))

    # Footer
    story.append(Spacer(1, 1 * inch))
    story.append(Paragraph("Report generated by AWS Cloud Risk Analyzer",
                           ParagraphStyle('Footer', parent=styles['Normal'],
                                          alignment=TA_CENTER, textColor=colors.gray)))

    # Build PDF
    doc.build(story)
    print(f"PDF report generated: {filename}")


if __name__ == "__main__":
    create_pdf_report()
