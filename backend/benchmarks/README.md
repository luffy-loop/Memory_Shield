

\# MemoryShield Security Benchmark



\## Overview



A reproducible offline evaluation framework for

measuring AI memory security and threat detection.



\## Dataset



\- Total samples: 200

\- Attack samples: 120

\- Benign samples: 60

\- Sensitive samples: 20

\- Security categories: 8



\## Baseline Results



| Metric | Value |

|---|---:|

| Policy Accuracy | 35.50% |

| Detection Accuracy | 42.78% |

| Precision | 72.97% |

| Recall | 22.50% |

| F1 Score | 34.39% |

| False Positive Rate | 16.67% |

| False Negative Rate | 77.50% |

| Average Latency | 0.1188 ms |



\## Run the Benchmark



From the backend directory:



&#x20;   python -m benchmarks.generate\_dataset

&#x20;   python -m benchmarks.run\_benchmark



\## Run Automated Tests



&#x20;   python -m pytest tests -v



\## Identified Weaknesses



\- Limited recognition of attack paraphrases.

\- Weak detection of obfuscated instructions.

\- Context-insensitive sensitive data detection.

\- Insufficient memory poisoning detection.

\- Authority impersonation detection gaps.

\- Uncalibrated risk thresholds.

\- Overlapping regex pattern scoring.



\## Limitations



The dataset contains synthetic, manually designed

development samples and templated examples.



It is not an independent real-world validation dataset.



Hindsight learning and stateful contradiction detection

are excluded from offline evaluation.



Binary metrics exclude sensitive samples.

Review and quarantine are counted as detection.

Policy accuracy requires an exact action match.



Undefined metric ratios are reported as zero.



Latency is machine-dependent.



\## Future Improvements



\- Text normalization

\- Context-aware detection

\- Semantic threat classification

\- Risk calibration

\- Memory governance

\- Independent holdout evaluation



