// Batch Digital Sign list action for the supported DocTypes. Wraps (does not replace) any
// existing list view settings, e.g. those from ERPNext.
(function () {
	if (window.__dsc_list_registered) return;
	window.__dsc_list_registered = true;

	const DOCTYPES = ["Sales Invoice", "Purchase Invoice", "Payment Entry", "Delivery Note", "Purchase Order"];
	const can_sign = () => frappe.user.has_role("DSC Signer") || frappe.user.has_role("System Manager");

	DOCTYPES.forEach((dt) => {
		const settings = (frappe.listview_settings[dt] = frappe.listview_settings[dt] || {});
		const orig_onload = settings.onload;
		settings.onload = function (listview) {
			if (orig_onload) orig_onload.call(this, listview);
			if (!can_sign()) return;
			listview.page.add_action_item(__("Batch Digital Sign"), () => batch_sign(listview, dt));
		};
	});

	function batch_sign(listview, doctype) {
		const names = listview.get_checked_items().map((d) => d.name);
		if (!names.length) return frappe.msgprint(__("Select documents first"));
		const d = new frappe.ui.Dialog({
			title: __("Batch Sign"),
			fields: [{
				label: __("Profile"), fieldname: "profile", fieldtype: "Link", options: "DSC Signature Profile", reqd: 1,
				get_query: () => ({ filters: { document_type: doctype, active: 1 } }),
			}],
			primary_action_label: __("Sign All"),
			primary_action(values) {
				d.hide();
				frappe.call({
					method: "dsc_signer.api.batch_sign",
					args: { doctype, names, profile: values.profile },
					freeze: true,
					freeze_message: __("Signing documents..."),
					callback(r) {
						show_result(r.message || []);
						listview.refresh();
					},
				});
			},
		});
		d.show();
	}

	function show_result(results) {
		const rows = results
			.map((r) => `<p>${r.status === "Signed" ? "✅" : "❌"} <b>${frappe.utils.escape_html(r.doc)}</b> — ${frappe.utils.escape_html(r.status)}</p>`)
			.join("");
		frappe.msgprint({ title: __("Batch Signing Result"), message: `<div style="max-height:300px;overflow:auto">${rows}</div>`, wide: true });
	}
})();
