# Gopher TOTP

A minimal CLI to generate TOTP codes from a Base32 secret.

* Reads the TOTP secret from stdin.
* Prints the 6-digit code, formatted `XXX-XXX`.
* Automatically updates every 30s.
* Copies the current code to the clipboard (if available).

## Usage

```bash
echo 'JBSWY3DPEHPK3PXP' | gopher-totp
```
```
Ctrl+C to exit.
Expires in: 13s | Code: 944-391
```

## GNU Pass Integration

You can pipe a TOTP secret stored in [pass](https://www.passwordstore.org) directly into `gopher-totp`:

```bash
pass show totp/example.com | sed -n '1p' | gopher-totp
```

Or create a convenient alias:

```bash
alias pass-totp='sed -n '1p' | gopher-totp'
pass show totp/example.com | pass-totp
```
