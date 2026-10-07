# CareBridge threat model

~~~mermaid
graph TD
    PDF[Uploaded PDF / hidden instructions] --> PH[Patient Helper]
    CHAT[Patient chat] --> PH
    PH --> PR[(Patient Records)]
    PH --> EMAIL[Email]
    CALL[Deepfake CFO video call] --> BILL[Billing Agent]
    BILL --> INV[(Invoices)]
    BILL --> PAY[Payment Gateway]
    CODE[Public code repository] --> KEY[Billing API credential]
    KEY --> BILL
    PH --> MS[MemoryShield policy + data-loss guard]
    BILL --> MS
    KEY --> CM[Credential Manager]
    MS --> AUDIT[Audit + Incident Trail]
    MS --> HUMAN[Human Approval]
    MS --> QUAR[Quarantine / Kill Switch]
    CM --> AUDIT
~~~

## Untrusted-input boundaries

1. Uploaded PDF content is untrusted and must never authorize patient-record or email actions.
2. Patient chat is untrusted and must be separated from tool authorization.
3. Video/voice identity is not sufficient evidence for payment approval.
4. Source repositories are untrusted credential stores; secrets must not be committed.
5. External destinations are higher risk than internal CareBridge destinations.

## Incident mapping

| Incident | Attack path | Required control | Evidence |
|---|---|---|---|
| PDF exfiltration | PDF -> Patient Helper -> external email | data-loss block + least privilege + audit | pdf_prompt_injection |
| €480k transfer | deepfake call -> Billing Agent -> payment gateway | human approval + independent verification | payment_deepfake |
| Public API key | repository -> static credential -> Billing Agent | short-lived scoped lease + rotation | credential_exposure |
