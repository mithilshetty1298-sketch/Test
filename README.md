┌──────────┐     mTLS/HTTPS     ┌─────────────┐     HTTPS/mTLS      ┌─────────────────────────────────────────┐
│          │ ──────────────────▶ │             │ ──────────────────▶ │           SERVER A (RHEL 9)             │
│   VISA   │                    │    APIGEE   │                     │  ┌─────────────┐    ┌────────────────┐  │
│          │ ◀────────────────── │   GATEWAY   │ ◀────────────────── │  │   DECODER   │───▶│ SCREENING BOX  │  │
└──────────┘                    └─────────────┘                     │  │ APPLICATION │    │  (Fircosoft V6)│  │
                                                                     │  └──────┬──────┘    └───────┬────────┘  │
                                                                     │         │                   │           │
                                                                     └─────────┼───────────────────┼───────────┘
                                                                               │                   │
                                                          mTLS                 │                   │ (local/IPC)
                                                     ┌────────────────────┐   │                   │
                                                     │  BCCKMS SERVER     │◀──┘                   ▼
                                                     │  (CADP / Thales)   │         ┌─────────────────────────┐
                                                     └────────────────────┘         │   SERVER B (RHEL 9)     │
                                                                                    │   ALERT CONTROLLER      │
                                                                                    └─────────────────────────┘




                                              Receive encrypted payload
        │
        ▼
Extract keyId from payload header
        │
        ▼
Check local in-memory key cache (KeyCacheManager)
        │
   ┌────┴────┐
  HIT       MISS
   │         │
   │         ▼
   │   Call BCCKMS over mTLS → retrieve private key material
   │   Cache key with TTL (see §3 for caching strategy)
   │         │
   └────┬────┘
        ▼
Decrypt payload using retrieved key
(AES-256-GCM or RSA-OAEP depending on Visa's scheme)
        │
        ▼
Validate decrypted payload (JSON schema validation)
        │
        ▼
Forward to Screening Box                                      
