# Gopher TOTP

A minimal CLI to generate TOTP codes from a Base32 secret or `otpauth://` URI.

---

# Usage

## Base32 secret

```bash
echo "JBSWY3DPEHPK3PXP" | gopher-totp
```

Example output:

```
Ctrl+C to exit.
Expires in: 13s | Code: 944391
```

---

## otpauth URI

You can also pass a full TOTP provisioning URI:

```bash
echo "otpauth://totp/example?secret=JBSWY3DPEHPK3PXP&period=30&digits=6" | gopher-totp
```

The URI values are used as defaults but can still be overridden by CLI flags.

Example:

```bash
echo "JBSWY3DPEHPK3PXP" | gopher-totp --pretty --clip
```

---

# GNU Pass Integration

You can pipe a TOTP secret stored in `pass` directly into `gopher-totp`:

```bash
pass show totp/example.com | sed -n '1p' | gopher-totp
```

Or create a convenient alias:

```bash
alias pass-totp='sed -n "1p" | gopher-totp'
pass show totp/example.com | pass-totp
```
