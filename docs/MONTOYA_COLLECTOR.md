# Burp Montoya Collector

This extension is the Burp-side collector for the local redaction gateway. It is
kept separate from the Python CLI under `extensions/montoya-collector/`.

## Scope

- The extension uses the Java Montoya API.
- It reads Proxy HTTP history with a `ProxyHistoryFilter`.
- It accepts only items whose request is in Burp suite scope.
- Raw request and response values are never logged.
- Raw values are handed off only to an HTTP endpoint on loopback.
- The local receiver must run the existing `generate` and `verify` policy before
  any output is copied into ChatGPT, Codex, issues, or documentation.

## Build

The Gradle project uses Montoya API `2026.4` as a `compileOnly` dependency. Burp
provides the API at runtime when the JAR is loaded.

```powershell
cd extensions\montoya-collector
.\gradlew.bat clean build
```

The JAR is created under `build/libs/`. Build outputs are ignored by Git.
The Gradle Wrapper pins Gradle `9.5.1` and verifies the distribution checksum.

## Load in Burp

1. Open Burp Suite.
2. Go to Extensions -> Installed.
3. Click Add.
4. Select Java as the extension type.
5. Select the built JAR under `extensions\montoya-collector\build\libs\`.

## Handoff

The default handoff URL is:

```text
http://127.0.0.1:8765/ingest/burp-history
```

You can override it with:

```powershell
$env:BURP_AI_REDACTION_GATEWAY_URL = "http://127.0.0.1:8765/ingest/burp-history"
```

The extension rejects non-loopback URLs. This prevents accidental submission of
raw traffic to remote services. The Python receiver for this endpoint is a
follow-up integration slice; this first slice only establishes the Burp collector
and transport boundary.

## Safety Rules

- Do not add raw Burp traffic to this repository.
- Do not log request or response values from the extension.
- Keep real exports and local handoff artifacts under ignored folders such as
  `local_only/`, `out/`, `raw/`, or `raw_vault/`.
- Continue to run `python -m burp_ai_redaction_gateway verify --input out`
  before using generated output.
- Continue to run Gitleaks before pushing.

## References

- PortSwigger: Creating Burp extensions
  https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating
- PortSwigger Montoya API Javadoc
  https://portswigger.github.io/burp-extensions-montoya-api/javadoc/
