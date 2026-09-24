"""Synthetic threat-lab scenario generators.

Produces realistic SYNTHETIC security telemetry as raw JSON log lines ready
for POST /api/v1/ingest. Every line is marked synthetic=true with a scenario
name. Uses only documentation IP ranges (TEST-NET-1/2/3). No real
credentials, secrets, or exploit payloads.
"""