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
@Bean
public NAESession naeSession() throws Exception {
    // 1. Verify provider is registered
    Provider p = Security.getProvider("IngrianProvider");
    System.out.println(">>> IngrianProvider registered: " + (p != null));
    System.out.println(">>> Provider class: " + (p != null ? p.getClass().getName() : "NULL"));

    // 2. Verify config is being read correctly
    System.out.println(">>> username: " + cadpProperties.getConfig("username"));
    System.out.println(">>> password: " + cadpProperties.getConfig("password"));
    System.out.println(">>> NAE_IP.1: " + cadpProperties.getConfig("NAE_IP.1"));
    System.out.println(">>> NAE_Port: " + cadpProperties.getConfig("NAE_Port"));
    System.out.println(">>> Key_Store_Location: " + cadpProperties.getConfig("Key_Store_Location"));
    System.out.println(">>> Client_Cert_Alias: " + cadpProperties.getConfig("Client_Cert_Alias"));

    // 3. Verify configInputStream content
    StringBuilder sb = new StringBuilder();
    cadpProperties.getConfigs().forEach((k, v) -> 
        sb.append(k).append("=").append(v).append("\n"));
    System.out.println(">>> Full config being passed to IngrianProvider:\n" + sb);

    // 4. Verify keystore file actually exists
    String ksPath = cadpProperties.getConfig("Key_Store_Location");
    System.out.println(">>> Keystore file exists: " + new java.io.File(ksPath).exists());

    String username = cadpProperties.getConfig("username");
    String password = cadpProperties.getConfig("password");

    return NAESession.getSession(username, password.toCharArray());
}
