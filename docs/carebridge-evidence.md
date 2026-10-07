# CareBridge Challenge E — Technical Evidence Appendix

This is a controlled simulation of the fictional CareBridge incidents. It uses synthetic data only and does not contact real patient systems, payment gateways, repositories, or AI services.

## Control matrix

| Requirement | Implementation | Evidence |
|---|---|---|
| Incident simulations | backend/app/carebridge/simulator.py | POST /carebridge/simulate |
| PDF prompt injection | Untrusted source + external medical payload | Expected BLOCK |
| €480k payment | Financial + payment-gateway risk scoring | Expected REVIEW + pending approval |
| Credential exposure | Scoped short-lived lease | Old lease invalid after rotation |
| Threat model | Mermaid + SVG | carebridge/threat_model.md |
| Dashboard | Agent Security control plane | Counters, agents, audit |
| Tests | Pytest scenario tests | backend/tests/test_carebridge.py |

## Evidence capture checklist

1. Agent Security — registered agents and allowed/blocked/review counters.
2. Action Audit — Patient Helper blocked action and Billing Agent review action.
3. Approvals — pending €480,000 payment approval.
4. Incidents — policy-triggered security incidents.
5. Agent status — quarantine/disabled control where applicable.
6. POST /carebridge/simulate response showing all three outcomes.

Never include real credentials, patient records, personal data, or payment information in screenshots.

## Expected results

- PDF scenario: BLOCK, risk 100, incident created.
- Payment scenario: REVIEW, human approval pending.
- Credential scenario: old lease invalid after rotation; new scoped lease valid.

## Test command

~~~bash
cd backend
pytest -q tests/test_agent_security.py tests/test_carebridge.py
~~~
