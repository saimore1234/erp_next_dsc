import frappe


def ensure_roles():
	"""Role that may digitally sign documents. System Manager always can."""
	if not frappe.db.exists("Role", "DSC Signer"):
		frappe.get_doc({"doctype": "Role", "role_name": "DSC Signer", "desk_access": 1}).insert(
			ignore_permissions=True
		)
