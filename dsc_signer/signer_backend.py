"""Chooses the cryptographic signer.

* Software Certificate (Test Only): PFX from DSC Settings. Refused unless the site is in
  developer mode or `dsc_allow_software_cert` is set in site_config.json, so a production site
  can't silently sign with a file-based key.
* Hardware Token (Agent): the private key stays on the USB token; signing is done by a local
  agent on the user's PC (prepare-hash / complete flow). Not implemented yet.
"""

import frappe
from frappe import _
from pyhanko.sign import signers

SOFTWARE = "Software Certificate (Test Only)"
HARDWARE = "Hardware Token (Agent)"


def get_signer():
    """Return (pyHanko signer, signing_method label)."""
    settings = frappe.get_single("DSC Settings")
    method = settings.signing_method or SOFTWARE

    if method == HARDWARE:
        frappe.throw(
            _(
                "Hardware token signing needs the DSC Signing Agent on the signer's PC, which is not "
                "installed/enabled yet. Use the software test certificate only for testing."
            ),
            title=_("Token agent not available"),
        )

    if not (frappe.conf.developer_mode or frappe.conf.get("dsc_allow_software_cert")):
        frappe.throw(
            _(
                "Software certificates are not allowed on this site. Production signing must use a "
                "hardware DSC token."
            ),
            title=_("Software certificate blocked"),
        )

    if not settings.attach_vmcx:
        frappe.throw(_("Certificate not configured in DSC Settings"))

    file_doc = frappe.get_doc("File", {"file_url": settings.attach_vmcx})
    pfx_bytes = file_doc.get_content()
    if isinstance(pfx_bytes, str):
        pfx_bytes = pfx_bytes.encode("latin-1")
    password = settings.get_password("certificate_password", raise_exception=False)
    try:
        signer = signers.SimpleSigner.load_pkcs12_data(
            pfx_bytes, [], passphrase=password.encode() if password else None
        )
    except Exception:
        frappe.throw(_("Could not open the certificate file. Check the file and password in DSC Settings."))
    return signer, "Software Test Certificate"
