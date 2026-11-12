// Digital Sign button for Sales Invoice, Purchase Invoice, Payment Entry, Delivery Note and
// Purchase Order. Shown only to users with the DSC Signer / System Manager role, on submitted
// documents. The server enforces the same rules.
(function () {
	if (window.__dsc_form_registered) return;
	window.__dsc_form_registered = true;

	const DOCTYPES = ["Sales Invoice", "Purchase Invoice", "Payment Entry", "Delivery Note", "Purchase Order"];
	const can_sign = () => frappe.user.has_role("DSC Signer") || frappe.user.has_role("System Manager");

	DOCTYPES.forEach((dt) => {
		frappe.ui.form.on(dt, {
			refresh(frm) {
				if (frm.doc.docstatus !== 1 || !can_sign()) return;
				frm.add_custom_button(__("Digital Sign"), () => open_signature_dialog(frm), __("Actions"));
			},
		});
	});

	function open_signature_dialog(frm) {
		frappe.call({
			method: "dsc_signer.api.get_profiles",
			args: { doctype: frm.doc.doctype },
			callback(r) {
				const profiles = r.message || [];
				if (!profiles.length) {
					frappe.msgprint(__("No active DSC Signature Profile exists for {0}.", [frm.doc.doctype]));
					return;
				}
				const d = new frappe.ui.Dialog({
					title: __("Select Signature Profile"),
					fields: [{ label: __("Profile"), fieldname: "profile", fieldtype: "Select", options: profiles, default: profiles[0], reqd: 1 }],
					primary_action_label: __("Sign"),
					primary_action(values) {
						d.hide();
						call_api(frm, "sign_with_profile", values.profile, __("Signing document..."), () => {
							frappe.show_alert({ message: __("Document signed"), indicator: "green" });
							frm.reload_doc();
						});
					},
					secondary_action_label: __("Preview"),
					secondary_action() {
						call_api(frm, "preview_with_profile", d.get_value("profile"), __("Generating preview..."), (r) => {
							if (r.message) window.open(r.message);
						});
					},
				});
				d.show();
			},
		});
	}

	function call_api(frm, method, profile, msg, cb) {
		frappe.call({
			method: "dsc_signer.api." + method,
			args: { docname: frm.doc.name, profile },
			freeze: true,
			freeze_message: msg,
			callback: cb,
		});
	}
})();
