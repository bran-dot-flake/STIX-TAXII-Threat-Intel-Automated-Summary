# Security boundaries

This is a private defensive lab. Bind both UIs to VM loopback and use SSH forwarding. There are no exposed database, cache, broker, S3, or Ollama ports in Compose. The pipeline runs as an ordinary user and cannot execute model tools. It never opens URLs found inside intelligence.

Treat feeds, source recommendations, platform search results and model responses as untrusted. The model sees bounded title/description excerpts with opaque evidence IDs. JSON validation accepts only those IDs and exact contiguous source excerpts; facts, URLs, dates, indicator values and actions are rendered from source records. This prevents the model from adding unsupported facts but **does not establish source truth, prevent misleading selection, or make quoted source instructions safe to follow**. There are no inferred ATT&CK mappings or actor relationships. Markdown/HTML from source text is escaped and indicators are defanged.

HTTP enforces response/time limits, verifies TLS, rejects redirects and embedded URL credentials, and retries only reads. Credentials are sent only to explicitly configured platform URLs. Use HTTP platform URLs only on VM loopback or the isolated Compose bridge; use HTTPS with valid certificates elsewhere. No certificate-verification bypass is provided. Malicious indicator URLs are never fetched.

`.env`, SQLite state, real reports, assessments and operational logs are ignored by Git. Generate `.env` exclusively with mode 0600; Windows users must restrict its ACL themselves. Never attach it to an issue. Container admins can inspect environment secrets; initial API credentials use lab administrators so deployment can bootstrap. Create dedicated least-privilege API users after validating integration and rotate the initial credentials through a deliberate migration. Never expose this setup as an Internet service.

The LLM receives no API keys, host environment, file access or execution tools. A failed or malformed model response generates a clearly degraded deterministic report, exits 2 and leaves the queue pending. Feed/platform failures exit 1 without acknowledging unfinished reports. A lock prevents overlapping jobs. Report files are written atomically, and private systemd service files use umask 0077.

Do not run intelligence lookup/enrichment against third-party targets without authorization. Nothing in this project probes IOCs, blocks traffic, sends notifications or publishes intelligence automatically.

Report vulnerabilities privately to the repository owner through GitHub's available private reporting features. Avoid public issues containing secrets, private reports, or infrastructure addresses.
