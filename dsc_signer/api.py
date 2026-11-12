import hashlib

import frappe
from frappe import _
from frappe.utils import get_datetime, now_datetime
from frappe.utils.file_manager import save_file
from frappe.utils.pdf import get_pdf

from dsc_signer.pdf_signer import sha256_hex, sign_pdf_bytes, verify_pdf_bytes
from dsc_signer.signer_backend import get_signer

SIGNER_ROLES = ("DSC Signer", "System Manager")
SUPPORTED_DOCTYPES = (
    "Sales Invoice",
    "Purchase Invoice",
    "Payment Entry",
    "Delivery Note",
    "Purchase Order",
)


def _require_signer_role():
    if not set(SIGNER_ROLES) & set(frappe.get_roles()):
        frappe.throw(_("You are not authorized to digitally sign documents."), frappe.PermissionError)


def _get_profile(profile):
    prof = frappe.get_doc("DSC Signature Profile", profile)
    if not prof.active:
        frappe.throw(_("Profile {0} is not active").format(profile))
    if prof.document_type not in SUPPORTED_DOCTYPES:
        frappe.throw(_("Digital signing is not enabled for {0}").format(prof.document_type))
    return prof


def _already_signed(doctype, name):
    return frappe.db.exists(
        "DSC Signing Log",
        {"reference_doctype": doctype, "reference_name": name, "status": "Success"},
    )


@frappe.whitelist()
def get_profiles(doctype=None):
    _require_signer_role()
    if not doctype:
        return []
    return frappe.get_all(
        "DSC Signature Profile", filters={"document_type": doctype, "active": 1}, pluck="name"
    )


def _generate_pdf(doc, prof):
    html = frappe.get_print(doc.doctype, doc.name, print_format=prof.print_format)
    return get_pdf(html)


def _log(doc, prof, status, **extra):
    log = frappe.get_doc(
        {
            "doctype": "DSC Signing Log",
            "reference_doctype": doc.doctype,
            "reference_name": doc.name,
            "profile": prof.name,
            "status": status,
            "signed_by": frappe.session.user,
            "signed_on": now_datetime(),
            "document_modified": doc.modified,
            **extra,
        }
    )
    log.insert(ignore_permissions=True)
    return log


@frappe.whitelist()
def sign_with_profile(docname=None, profile=None):
    _require_signer_role()
    if not docname or not profile:
        frappe.throw(_("Missing document or profile"))

    prof = _get_profile(profile)
    doc = frappe.get_doc(prof.document_type, docname)
    doc.check_permission("read")
    doc.check_permission("print")

    if doc.docstatus != 1:
        frappe.throw(_("Only submitted documents can be digitally signed."))

    # Serialize concurrent signing of the same document, then check for duplicates.
    frappe.db.get_value(doc.doctype, doc.name, "modified", for_update=True)
    if not prof.allow_re_sign and _already_signed(doc.doctype, doc.name):
        frappe.throw(_("{0} is already digitally signed. Re-signing is disabled in the profile.").format(docname))

    signer, method = get_signer()
    unsigned = _generate_pdf(doc, prof)
    company = doc.get("company") or frappe.defaults.get_global_default("company") or ""
    signed, d = sign_pdf_bytes(unsigned, signer, prof, company)

    safe = docname.replace("/", "_")
    file_doc = save_file(f"{safe}_SIGNED.pdf", signed, doc.doctype, doc.name, is_private=1)
    _log(
        doc,
        prof,
        "Success",
        signing_method=method,
        signer_name=d["signer_name"],
        issuer=d["issuer"],
        serial_number=d["serial_number"],
        valid_from=d["valid_from"],
        valid_to=d["valid_to"],
        certificate_fingerprint=d["fingerprint"],
        unsigned_hash=sha256_hex(unsigned),
        signed_hash=sha256_hex(signed),
        signed_file=file_doc.file_url,
    )
    return _("Document signed and attached successfully")


@frappe.whitelist()
def batch_sign(doctype=None, names=None, profile=None):
    _require_signer_role()
    if not doctype or not names or not profile:
        frappe.throw(_("Missing parameters"))
    prof = _get_profile(profile)
    if prof.document_type != doctype:
        frappe.throw(_("Profile {0} is for {1}, not {2}").format(profile, prof.document_type, doctype))

    results = []
    for name in frappe.parse_json(names):
        try:
            sign_with_profile(name, profile)
            frappe.db.commit()
            results.append({"doc": name, "status": "Signed"})
        except Exception as e:
            frappe.db.rollback()
            results.append({"doc": name, "status": str(e)})
    return results


@frappe.whitelist()
def preview_with_profile(docname=None, profile=None):
    """Unsigned PDF so the user can check the layout. Placeholder box only, nothing is signed."""
    _require_signer_role()
    prof = _get_profile(profile)
    doc = frappe.get_doc(prof.document_type, docname)
    doc.check_permission("print")
    pdf = _generate_pdf(doc, prof)
    return save_file(
        f"{docname.replace('/', '_')}_preview.pdf", pdf, doc.doctype, doc.name, is_private=1
    ).file_url


@frappe.whitelist()
def verify_signing_log(log):
    """Re-verify a signed file: signature integrity, and whether the ERPNext document has been
    modified since it was signed."""
    _require_signer_role()
    entry = frappe.get_doc("DSC Signing Log", log)
    if entry.status != "Success" or not entry.signed_file:
        frappe.throw(_("This log entry has no signed file"))
    entry.check_permission("read")

    content = frappe.get_doc("File", {"file_url": entry.signed_file}).get_content()
    if hashlib.sha256(content).hexdigest() != entry.signed_hash:
        file_changed = True
    else:
        file_changed = False

    current_modified = frappe.db.get_value(entry.reference_doctype, entry.reference_name, "modified")
    return {
        "signed_file_hash_matches_log": not file_changed,
        "document_modified_since_signing": bool(
            current_modified and get_datetime(current_modified) != get_datetime(entry.document_modified)
        ),
        "signatures": verify_pdf_bytes(content),
    }


def auto_sign_on_submit(doc, method=None):
    """Never blocks submission: a failed signing is logged and can be retried manually.
    Token-based signing needs the user's PC, so auto-sign only works with the test certificate."""
    if doc.doctype not in SUPPORTED_DOCTYPES:
        return
    profiles = frappe.get_all(
        "DSC Signature Profile",
        filters={"document_type": doc.doctype, "active": 1, "auto_sign_on_submit": 1},
        pluck="name",
    )
    if not profiles:
        return
    try:
        sign_with_profile(doc.name, profiles[0])
    except Exception:
        frappe.log_error(title=f"DSC auto-sign failed: {doc.doctype} {doc.name}")
        frappe.msgprint(_("Automatic digital signing failed. You can retry with Digital Sign."), indicator="orange")
