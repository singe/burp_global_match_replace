# Burp Header Strip Extension

Provides a system-wide match & replace table that applies to all Burp tools (including Burp AI). This goes beyond Proxy Match & Replace, which only affects Proxy.

## Build

```bash
./gradlew clean jar
```

The built JAR is in `build/libs/burp-header-strip-1.0.0.jar`.

## Load in Burp

1. Burp Suite → Extensions → Add
2. Extension type: Java
3. Select the JAR from `build/libs/`

## Configure

Open the **Header Strip** tab:

- **Match & Replace**: add rules that apply to request/response messages system-wide.
- Example rules are pre-populated and disabled by default.

### Rule fields

- **Enabled**: toggle the rule on/off.
- **Scope**: Request, Response, or Both.
- **Mode**: Literal or Regex.
- **Match**: the pattern to search for.
- **Replace**: the replacement string.
- **Comment**: description of what the rule does.

Rules are persisted in extension settings.

## Notes

- Matching and replacement apply to the full raw HTTP message (headers + body).
- Regex rules use Java regex syntax.
- Binary response bodies may be altered if they match patterns.
