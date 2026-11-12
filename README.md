# ERPNext DSC Signer (`dsc_signer`)

Digitally signs ERPNext print-format PDFs with a **genuine cryptographic PDF signature** and a
**visible signature** (a real PDF signature field, not an image pasted on the page).

Frappe / ERPNext **v15**. Based on [Inaaya14march/dsc_signer](https://github.com/Inaaya14march/dsc_signer)
(MIT); the signing core, security model and audit trail were reworked here.

## Features

- Visible signature in the upper-right (or any corner / custom position) with the signatory name in
  large text, issuer, certificate serial number, company, signing date/time and certificate validity.
- Signed with pyHanko; the appearance is part of the signed revision, so any change to the document
  invalidates the signature in Adobe Acrobat.
- Works with Sales Invoice, Purchase Invoice, Payment Entry, Delivery Note and Purchase Order, using a
  **DSC Signature Profile** per document type and print format.
- **DSC Signing Log**: append-only audit trail (user, time, certificate, SHA-256 of unsigned/signed PDF).
- Only users with the **DSC Signer** role (or System Manager) can sign; only submitted documents;
  duplicate signing is blocked unless the profile allows re-signing.
- Batch signing from list views; auto-sign on submit never blocks submission.
- `verify_signing_log` re-verifies a signed file and reports whether the ERPNext document changed
  after signing.

## Signing methods (DSC Settings -> Signing Method)

| Method | Status |
|---|---|
| Software Certificate (Test Only) | Working. Disabled unless developer mode or `dsc_allow_software_cert` is set in `site_config.json`. **Never use in production.** |
| Hardware Token (Agent) | Planned: a local agent on the signer's PC signs the document hash with the USB token (PKCS#11). The private key never leaves the token and the PIN is never stored. |

## Install

```
bench get-app https://github.com/saimore1234/erp_next_dsc.git
bench --site <site> install-app dsc_signer
bench --site <site> migrate
```

PDF generation needs `wkhtmltopdf` (patched Qt build, 0.12.6.1-2) installed on the server.

## Security notes

- Do not commit certificates or keys (`*.pfx`, `*.p12`, `*.pem`, `*.key` are git-ignored).
- The test PFX password is stored encrypted by Frappe (Password field).
