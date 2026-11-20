from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.application.ports.reports import ReportDocument
from app.domain.services.report_builder import SEVERITY_LABELS, SEVERITY_ORDER
from app.domain.value_objects.severity import Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#b71c1c"),
    Severity.HIGH: colors.HexColor("#e65100"),
    Severity.MEDIUM: colors.HexColor("#f9a825"),
    Severity.LOW: colors.HexColor("#2e7d32"),
    Severity.INFO: colors.HexColor("#546e7a"),
}
STATUS_LABELS = {
    "pending": "Pendiente",
    "in_progress": "En curso",
    "done": "Hecha",
    "dismissed": "Descartada",
}


class ReportlabPdfRenderer:
    def render(self, document: ReportDocument) -> bytes:
        buffer = BytesIO()
        pdf = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            title=f"Reporte SafeIT - {document.domain}",
            author="SafeIT",
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        body = ParagraphStyle("body", parent=styles["BodyText"], leading=15)
        cell = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=9, leading=11)
        story: list[object] = [
            Paragraph("Reporte de pruebas controladas", styles["Title"]),
            Paragraph(
                f"Dominio: <b>{escape(document.domain)}</b><br/>"
                f"Generado: {document.created_at:%Y-%m-%d %H:%M} UTC<br/>"
                f"Escaneo: {document.scan_id}",
                body,
            ),
            Spacer(1, 0.6 * cm),
            Paragraph("Resumen ejecutivo", styles["Heading2"]),
            Paragraph(escape(document.summary), body),
            Spacer(1, 0.4 * cm),
            Paragraph("Hallazgos por severidad", styles["Heading2"]),
            Paragraph(f"Total de hallazgos activos: <b>{document.total}</b>", body),
            Spacer(1, 0.2 * cm),
            self._chart(document),
            self._counts_table(document, cell),
            Spacer(1, 0.6 * cm),
            Paragraph("Recomendaciones por prioridad", styles["Heading2"]),
        ]
        if document.recommendations:
            story.append(self._recommendations_table(document, cell))
        else:
            story.append(Paragraph("Sin recomendaciones.", body))
        pdf.build(story)
        return buffer.getvalue()

    def _chart(self, document: ReportDocument) -> Drawing:
        drawing = Drawing(450, 160)
        chart = VerticalBarChart()
        chart.x, chart.y, chart.width, chart.height = 40, 25, 380, 115
        values = [document.counts.get(s, 0) for s in SEVERITY_ORDER]
        chart.data = [values]
        chart.categoryAxis.categoryNames = [SEVERITY_LABELS[s].capitalize() for s in SEVERITY_ORDER]
        chart.valueAxis.valueMin = 0
        chart.valueAxis.valueMax = max(max(values), 1)
        chart.valueAxis.valueStep = max(1, -(-max(values) // 5)) if max(values) else 1
        chart.barLabelFormat = "%d"
        chart.barLabels.nudge = 7
        for index, severity in enumerate(SEVERITY_ORDER):
            chart.bars[(0, index)].fillColor = SEVERITY_COLORS[severity]
        drawing.add(chart)
        return drawing

    def _counts_table(self, document: ReportDocument, cell: ParagraphStyle) -> Table:
        rows = [["Severidad", "Cantidad"]]
        rows += [
            [SEVERITY_LABELS[s].capitalize(), str(document.counts.get(s, 0))]
            for s in SEVERITY_ORDER
        ]
        table = Table(rows, colWidths=[6 * cm, 3 * cm])
        table.setStyle(_table_style())
        return table

    def _recommendations_table(self, document: ReportDocument, cell: ParagraphStyle) -> Table:
        rows: list[list[object]] = [["#", "Hallazgo", "Severidad", "Acción", "Estado"]]
        for rec in document.recommendations:
            rows.append(
                [
                    str(rec.priority),
                    Paragraph(f"{escape(rec.finding_title)}<br/>{escape(rec.url)}", cell),
                    SEVERITY_LABELS[rec.severity].capitalize(),
                    Paragraph(escape(rec.action), cell),
                    STATUS_LABELS[rec.status.value],
                ]
            )
        table = Table(
            rows, colWidths=[0.8 * cm, 5 * cm, 2.2 * cm, 6.2 * cm, 2.2 * cm], repeatRows=1
        )
        table.setStyle(_table_style())
        return table


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b0bec5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eceff1")]),
        ]
    )
