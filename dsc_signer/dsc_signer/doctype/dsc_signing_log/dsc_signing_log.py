import frappe
from frappe import _
from frappe.model.document import Document


class DSCSigningLog(Document):
	"""Append-only audit record. Rows are inserted by the signing API only."""

	def validate(self):
		if not self.is_new():
			frappe.throw(_("Signing log entries cannot be modified."))

	def on_trash(self):
		frappe.throw(_("Signing log entries cannot be deleted."))
