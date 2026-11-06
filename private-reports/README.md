# Encrypted private reports

The public website serves a generic password screen and an authenticated encrypted
package. The report, its metadata and every attachment are encrypted **before**
they enter this repository. Never add plaintext report inputs or passwords here.

## Build

Use Node.js with native Web Crypto. Generate a fresh high-entropy password (at
least 24 random URL-safe characters) into a file outside the repository, with
mode 0600. Do not pass a password on the command line, place it in a URL, or put
it in the manifest. Keep the source files and the manifest outside the repository.

The private manifest shape is:

```json
{
  "entrypoint": "report.html",
  "download": "documents.zip",
  "files": [
    {"name": "report.html", "type": "text/html", "source": "/private/report.html"},
    {"name": "documents.zip", "type": "application/zip", "source": "/private/documents.zip"}
  ]
}
```

From the repository root:

```sh
node private-reports/build.mjs /private/manifest.json /private/password.txt informes/opaque-report-id
node --test private-reports/crypto.test.mjs
```

The builder writes only `index.html` and `bundle.enc` to the report directory.
Review the scoped diff and test before deploying through the existing Pages
branch. Do not publish source documents, passwords, private manifests, screenshots
of unlocked reports or test logs containing their contents.

## Protection and limits

- AES-256-GCM, a fresh 96-bit IV and 128-bit tag; the versioned header is authenticated.
- PBKDF2-HMAC-SHA-256 with 600,000 iterations and a fresh 128-bit salt. The derived
  key is non-extractable in Web Crypto. Passwords are never sent to the server.
- Everything inside the package, including HTML, PDF and other downloads, is
  encrypted. Attachments become in-memory object URLs only after successful unlock.
- The password is not saved in URLs, cookies, local storage or session storage.
  Locking removes the viewer and revokes object URLs; reloading requires the password.
- This is encrypted static distribution, not server authentication. Public
  ciphertext can be copied and attacked offline, so a strong generated password
  is required. Changing the published password cannot revoke an older copied
  package or documents already downloaded by an authorized recipient.
- The existing HTTPS website and its JavaScript delivery remain trusted. This
  design does not protect against a compromised site serving altered unlock code.
  The report iframe contains trusted, authored report code, not arbitrary user HTML.

Primitive references: [Web Crypto AES-GCM](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams),
[key derivation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey),
[PBKDF2 work factor](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2).
