"""PDF signing core.

The visible signature is a genuine PDF signature field (AcroForm widget) whose appearance
stream is part of the signed revision, so Acrobat shows it as a signature and any change to
the page or the appearance invalidates the signature. Nothing is stamped onto page content.

The cryptographic signer is pluggable (software certificate for tests, token-backed signer
for production); this module never sees a private key unless the signer object holds one.
"""

import hashlib
import io
import os
import tempfile
from datetime import datetime

from PyPDF2 import PdfReader
from pyhanko import stamp
from pyhanko.pdf_utils import layout
from pyhanko.pdf_utils.content import ImportedPdfPage
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from reportlab.lib.colors import Color, black
from reportlab.pdfgen import canvas

MARGIN = 20
DEFAULT_BOX = (260, 100)  # width, height in points
MIN_BOX = (240, 95)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cert_details(cert) -> dict:
    """Human-readable facts about a certificate (asn1crypto x509.Certificate)."""
    subject = cert.subject.native
    issuer = cert.issuer.native
    return {
        "signer_name": subject.get("common_name") or subject.get("organization_name") or "",
        "organization": subject.get("organization_name") or "",
        "issuer": issuer.get("common_name") or issuer.get("organization_name") or "",
        "serial_number": format(cert.serial_number, "X"),
        "valid_from": cert["tbs_certificate"]["validity"]["not_before"].native.replace(tzinfo=None),
        "valid_to": cert["tbs_certificate"]["validity"]["not_after"].native.replace(tzinfo=None),
        "fingerprint": cert.sha256_fingerprint.replace(" ", ""),
        "self_signed": cert.self_signed != "no",
    }


def validate_certificate_now(details: dict) -> str:
    """Cheap, offline validity-window check shown on the signature. (Chain/revocation trust is
    decided by the PDF reader, e.g. Acrobat's trust store.)"""
    now = datetime.utcnow()
    if now < details["valid_from"]:
        return "Not yet valid"
    if now > details["valid_to"]:
        return "Expired"
    return "Within validity period"


def compute_box(page_w, page_h, placement, x, y, w, h):
    """Return (llx, lly, urx, ury) in PDF user space (origin bottom-left)."""
    placement = placement or "Upper Right"
    if placement == "Custom":
        llx = max(0, min(x, page_w - w))
        lly = max(0, min(y, page_h - h))
    else:
        llx = MARGIN if "Left" in placement else page_w - w - MARGIN
        lly = page_h - h - MARGIN if "Upper" in placement else MARGIN
    return (int(llx), int(lly), int(llx + w), int(lly + h))


def _render_appearance(path, w, h, company, details, signed_at, validity):
    """Draw the signature appearance (large name + certificate facts) as a one-page PDF that is
    then embedded in the signature field's appearance stream."""
    c = canvas.Canvas(path, pagesize=(w, h))
    c.setStrokeColor(Color(0.1, 0.25, 0.55))
    c.setLineWidth(1)
    c.rect(1, 1, w - 2, h - 2, fill=0)

    name = (details["signer_name"] or "Signatory")[:40]
    size = 16
    while size > 8 and c.stringWidth(name, "Helvetica-Bold", size) > w - 16:
        size -= 1
    c.setFillColor(Color(0.1, 0.25, 0.55))
    c.setFont("Helvetica-Bold", size)
    c.drawString(8, h - 8 - size, name)

    c.setFillColor(black)
    c.setFont("Helvetica", 6.5)
    y = h - 8 - size - 9
    lines = [
        "Digitally signed by " + (details["signer_name"] or "")[:45],
        ("Company: " + company)[:60] if company else "",
        "Issuer: " + (details["issuer"] or "")[:52],
        "Serial No: " + details["serial_number"][:44],
        "Date: " + signed_at.strftime("%d-%m-%Y %H:%M:%S"),
        "Certificate: " + validity,
    ]
    for line in lines:
        if not line:
            continue
        c.drawString(8, y, line)
        y -= 8.5
    c.save()


def get_pdf_info(pdf_bytes: bytes):
    reader = PdfReader(io.BytesIO(pdf_bytes))
    return reader, len(reader.pages)


def pick_page_index(total_pages, mode, page_number):
    if mode == "Last Page":
        return total_pages - 1
    # "All Pages" cannot be one cryptographic signature on every page; use the chosen page.
    return max(0, min((page_number or 1) - 1, total_pages - 1))


def sign_pdf_bytes(pdf_bytes: bytes, signer, profile, company: str = "", reason: str | None = None):
    """Sign `pdf_bytes` with `signer` (a pyHanko Signer). Returns (signed_bytes, details dict)."""
    reader, total = get_pdf_info(pdf_bytes)
    page_ix = pick_page_index(total, profile.signature_mode, profile.page_number)
    page = reader.pages[page_ix]
    page_w, page_h = float(page.mediabox.width), float(page.mediabox.height)

    # Below this size the certificate details would be clipped, so enforce a minimum.
    w = max(float(profile.box_widthponts or DEFAULT_BOX[0]), MIN_BOX[0])
    h = max(float(profile.box_hieghtponts or DEFAULT_BOX[1]), MIN_BOX[1])
    box = compute_box(
        page_w, page_h, profile.get("placement"), profile.x_positionpoints or 0,
        profile.y_positionpoints or 0, w, h,
    )

    details = cert_details(signer.signing_cert)
    signed_at = datetime.now()
    validity = validate_certificate_now(details)

    existing = len(PdfFileReader(io.BytesIO(pdf_bytes)).embedded_signatures)
    field_name = f"DSC_Signature_{existing + 1}"

    tmp_dir = tempfile.mkdtemp(prefix="dsc_")
    appearance = os.path.join(tmp_dir, "appearance.pdf")
    try:
        _render_appearance(appearance, w, h, company, details, signed_at, validity)

        style = stamp.TextStampStyle(
            stamp_text="",
            border_width=0,
            background=ImportedPdfPage(appearance),
            background_layout=layout.SimpleBoxLayoutRule(
                x_align=layout.AxisAlignment.ALIGN_MID,
                y_align=layout.AxisAlignment.ALIGN_MID,
                inner_content_scaling=layout.InnerScaling.SHRINK_TO_FIT,
            ),
        )
        meta = signers.PdfSignatureMetadata(
            field_name=field_name,
            md_algorithm="sha256",
            reason=reason or "Document approval",
            name=details["signer_name"],
        )
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer,
            stamp_style=style,
            new_field_spec=fields.SigFieldSpec(field_name, on_page=page_ix, box=box),
        )
        out = io.BytesIO()
        pdf_signer.sign_pdf(IncrementalPdfFileWriter(io.BytesIO(pdf_bytes)), output=out)
    finally:
        try:
            os.remove(appearance)
            os.rmdir(tmp_dir)
        except OSError:
            pass

    details.update(field_name=field_name, signed_at=signed_at, certificate_check=validity)
    return out.getvalue(), details


def verify_pdf_bytes(pdf_bytes: bytes) -> list[dict]:
    """Verify every embedded signature: integrity (document unchanged since signing) and
    cryptographic validity. Trust to a root CA is reported separately."""
    from pyhanko.sign.validation import validate_pdf_signature

    results = []
    for sig in PdfFileReader(io.BytesIO(pdf_bytes)).embedded_signatures:
        status = validate_pdf_signature(sig)
        results.append(
            {
                "field": sig.field_name,
                "intact": bool(status.intact),
                "valid": bool(status.valid),
                "trusted": bool(status.trusted),
                "coverage": str(status.coverage),
                # anything appended after the signature (edits, extra signatures, junk) shows up here
                "modified_after_signing": "ENTIRE_FILE" not in str(status.coverage),
                "modification_level": str(status.modification_level),
                "signer": sig.signer_cert.subject.native.get("common_name", ""),
            }
        )
    return results
