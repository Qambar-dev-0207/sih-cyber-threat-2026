from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


OUT = Path(__file__).with_name("SIH26145_hackathon_QA.pdf")

QA = [
    ("Problem and purpose", [
        ("1. What problem does the project solve?", "It detects cyber threats in high-security networks without creating a return path into the monitored network."),
        ("2. Who is the project for?", "It is designed for critical infrastructure, defence, intelligence, and other air-gapped environments."),
        ("3. What is the main idea in one sentence?", "Observe traffic passively, detect threats quickly, fuse the evidence, and prepare a safe response for human approval."),
        ("4. What makes the problem difficult?", "The system must detect attacks at high speed while remaining strictly passive and safe."),
        ("5. What is the project name?", "SIH26145 Autonomous Passive Network Threat Detection and Out-of-Band Countermeasure Generation."),
        ("6. What is the key security guarantee?", "The monitoring enclave never sends packets, opens outbound connections, or executes changes on the production network."),
        ("7. What is a data diode?", "A data diode is a hardware device that allows data to move in only one physical direction."),
        ("8. Why is passive monitoring important?", "A passive sensor observes traffic without probing or modifying the protected network."),
        ("9. What happens when an attack is detected?", "The platform creates a fused incident, explains the evidence, generates response artifacts, and waits for an authorized human."),
        ("10. What is the project value to an operator?", "It turns complex network signals into one understandable incident and a controlled response plan."),
    ]),
    ("Architecture and flow", [
        ("11. What is the complete processing flow?", "Traffic tap, Zeek telemetry, streaming bus, detectors, alert fusion, triage, countermeasures, and SOC review."),
        ("12. What does Zeek provide?", "Zeek converts observed traffic into structured connection, DNS, TLS, and fingerprint telemetry."),
        ("13. What is the streaming bus used for?", "It moves telemetry and raw alerts between pipeline components in a partitioned, scalable way."),
        ("14. What is CEP?", "Complex Event Processing correlates related alerts over time and combines them into one incident context."),
        ("15. Why fuse alerts?", "Fusion reduces alert noise and shows the full attack story instead of isolated warnings."),
        ("16. What does the dashboard show?", "It shows pipeline health, telemetry, detectors, incidents, risk evidence, and the complete scenario walkthrough."),
        ("17. What is the role of the walkthrough page?", "It presents the attack and response as a step-by-step storyboard for operators and judges."),
        ("18. Which backend framework is used?", "FastAPI is used for the API and real-time communication layer."),
        ("19. Which frontend framework is used?", "The dashboard is built with React and Vite."),
        ("20. How can the project run without infrastructure?", "Offline in-memory simulation mode reproduces the main detection and triage flow without Docker or a database."),
    ]),
    ("Threat detection", [
        ("21. How many streaming detectors are included?", "Six parallel detectors."),
        ("22. What does the DDoS detector find?", "It finds high-volume traffic and abnormal flow entropy associated with volumetric denial-of-service attacks."),
        ("23. What does the port-scan detector find?", "It tracks unusual distinct target ports or addresses to identify reconnaissance."),
        ("24. What does the exfiltration detector find?", "It looks for abnormal outbound-to-inbound byte ratios and unusual volume."),
        ("25. What does the DNS detector find?", "It looks for DGA-like domains, high entropy, long subdomains, and tunnelling patterns."),
        ("26. What does JA4 detection do?", "It compares TLS handshake fingerprints with known malicious or suspicious fingerprints and anomalies."),
        ("27. What does the beaconing detector find?", "It identifies periodic command-and-control traffic by analyzing timing and jitter."),
        ("28. What is JA4?", "JA4 is a compact fingerprint of TLS client or server handshake behavior."),
        ("29. What is Shannon entropy used for?", "It measures randomness and helps identify suspicious domains or unusual traffic distributions."),
        ("30. What is HyperLogLog used for?", "It estimates distinct targets efficiently with low memory, which is useful for port-scan detection."),
    ]),
    ("Triage and response", [
        ("31. How is risk calculated?", "The system combines detector weights, confidence, asset criticality, and multi-stage synergy into an explainable score."),
        ("32. What is a fused incident?", "It is one correlated security case containing alerts, timeline evidence, risk, techniques, and response options."),
        ("33. What is MITRE ATT&CK used for?", "It maps observed behavior to a common language of adversary techniques and tactics."),
        ("34. What is an attack narrative?", "It is a readable explanation of how the observed signals form a likely attack chain."),
        ("35. What does human-in-the-loop mean?", "A person reviews and approves the response before it can be deployed."),
        ("36. Why are countermeasures not auto-executed?", "Automatic changes could block legitimate systems or create an active attack path, so approval is mandatory."),
        ("37. Which response artifacts are generated?", "iptables, nftables, Cisco ACL, DNS RPZ, Snort or Suricata rules, and STIX 2.1 bundles."),
        ("38. What does syntax validation provide?", "It checks that a generated artifact is structurally valid before an operator reviews it."),
        ("39. What is out-of-band response?", "The response is exported through a separate approved channel rather than sent through the monitored link."),
        ("40. What does the operator approve?", "The operator approves the exact response artifact, its target, and its deployment decision."),
    ]),
    ("Demo and technical questions", [
        ("41. What scenario best demonstrates the project?", "The APT scenario demonstrates reconnaissance, command and control, and exfiltration as one multi-stage incident."),
        ("42. What other scenarios are available?", "DDoS, C2 beaconing, DNS tunnelling, and distributed port scanning are also available."),
        ("43. What does the APT demo prove?", "It proves that multiple detector signals can be correlated into one incident with a readable kill-chain story."),
        ("44. How does the demo remain reliable offline?", "It uses deterministic synthetic telemetry and an in-memory fallback, so it does not depend on external services."),
        ("45. How is the zero return path tested?", "Tests trap outbound sockets, HTTP calls, subprocess execution, and packet injection attempts."),
        ("46. How is high throughput tested?", "Stress tests replay large telemetry loads and check throughput, memory growth, loss, and latency."),
        ("47. What happens if the database is unavailable?", "The application can use mock or in-memory data so the demonstration remains available."),
        ("48. What is the strongest differentiator?", "The system combines passive-only security with explainable multi-detector correlation and human-approved response generation."),
        ("49. What is the main limitation?", "Generated responses still require an authorized operator and a separate deployment process."),
        ("50. What is the future scope?", "Future work can add more telemetry sources, production connectors, richer models, and stronger deployment governance."),
    ]),
]


def footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#D9DED5"))
    canvas.line(18 * mm, 14 * mm, 192 * mm, 14 * mm)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#687066"))
    canvas.drawString(18 * mm, 9 * mm, "SIH26145 | Hackathon preparation")
    canvas.drawRightString(192 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build():
    styles = getSampleStyleSheet()
    title = ParagraphStyle("Title", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25, leading=29, textColor=colors.HexColor("#151815"), alignment=TA_CENTER, spaceAfter=8)
    subtitle = ParagraphStyle("Subtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=10, leading=15, textColor=colors.HexColor("#687066"), alignment=TA_CENTER, spaceAfter=18)
    section = ParagraphStyle("Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=colors.HexColor("#151815"), spaceBefore=6, spaceAfter=9)
    question = ParagraphStyle("Question", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10.3, leading=13, textColor=colors.HexColor("#151815"), spaceAfter=3)
    answer = ParagraphStyle("Answer", parent=styles["Normal"], fontName="Helvetica", fontSize=9.4, leading=13, textColor=colors.HexColor("#424941"), spaceAfter=9)
    note = ParagraphStyle("Note", parent=styles["Normal"], fontName="Helvetica-Oblique", fontSize=9, leading=13, textColor=colors.HexColor("#687066"), alignment=TA_CENTER)

    story = [Spacer(1, 20 * mm), Paragraph("SIH26145", title), Paragraph("50 Hackathon Questions and Short Answers", subtitle)]
    cover = Table([[Paragraph("PASSIVE DETECTION  /  EXPLAINABLE TRIAGE  /  HUMAN APPROVAL", note)]], colWidths=[174 * mm])
    cover.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#DDF38D")), ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#A4BD52")), ("TOPPADDING", (0, 0), (-1, -1), 11), ("BOTTOMPADDING", (0, 0), (-1, -1), 11)]))
    story += [cover, Spacer(1, 10 * mm), Paragraph("Use this sheet to give consistent, clear answers during the judge discussion. Keep the first answer short, then explain the relevant screen or test when asked.", note), PageBreak()]

    for section_name, items in QA:
        story.append(Paragraph(section_name, section))
        for q, a in items:
            story.append(Paragraph(q, question))
            story.append(Paragraph(a, answer))
        story.append(Spacer(1, 3 * mm))

    doc = SimpleDocTemplate(str(OUT), pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=16 * mm, bottomMargin=20 * mm, title="SIH26145 Hackathon Questions and Answers", author="SIH26145 Team")
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(OUT)


if __name__ == "__main__":
    build()
