# maskdata

Mask sensitive data in text and files. Zero dependencies.

## Usage

```bash
# Pipe mode
echo "email: user@example.com" | maskdata mask

# File mode
maskdata mask config.log
maskdata mask config.log --in-place

# Scan only (detect without masking)
maskdata scan .env credentials.yml

# Filter types
maskdata mask --only=email,phone data.txt
```

## Detected Patterns

| Type | Example | Masked |
|------|---------|--------|
| email | user@example.com | u***@e*** |
| phone | +1-555-123-4567 | +1-***67 |
| ssn | 123-45-6789 | ***-**-6789 |
| credit_card | 4111-1111-1111-1234 | ****-****-****-1234 |
| ipv4 | 192.168.1.100 | 192.168.*.* |
| jwt | eyJhbG... | eyJ***.[REDACTED] |
| api_key | api_key=sk_live_xxx | [REDACTED] |
| aws_key | AKIAIOSFODNN7 | AKIA***REDACTED*** |

## Requirements

- Python 3.6+ (stdlib only)
