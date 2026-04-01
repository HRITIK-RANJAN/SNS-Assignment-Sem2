# Security Design Document

## Overall Philosophy
This Multi-Source Intrusion Detection System is built on the philosophy of cross-source validation. We assume single-channel signals, especially those typical of low-intensity port scans or noisy networks, inherently produce false positives. To combat this, the pipeline correlates data from two distinct, decoupled components (Network and Host sensors).

## Correlation Engine & The "Core Security Requirement"
The IDS enforces the primary core security requirement explicitly in the Correlation Engine (`src/correlation_engine.py`): *A High-severity alert is strictly the maximum assigned for unconfirmed single-channel anomalies*. 

### Rule Mechanisms
1. **Deduplication:** A cooldown threshold of 10s is applied globally per rule-signature by the Alert Manager. This minimizes DDOS of alerts to SEC-OPS and makes downstream parsing manageable.
2. **Contextual Scaling:** Multi-step deterministic rules (like the connection followed by login failure, success, and suspicious command execution — `MultiStepCompromise`) are explicitly classified as `Critical`. 
3. **Statistical Baselines:** We incorporate unsupervised detection by establishing a sliding window of request rates for sources. It handles minor fluctuations using variance standard deviations ($\sigma$), tracking $z_f$. The anomaly rules filter out single isolated high peaks but alert when z-scores exceed a predefined sigma of 3 consistently inside a 60-second window.

## Threat Model Handling
- **Port Scans and Brute Forces**: These trigger standard rate-based deterministic thresholds inside a sliding time window (60s). Scans are additionally classified by velocity (Fast/Slow).
- **Noise/Replay Injection:** A hashing mechanism matches identical sequential inputs over timestamps (skipping UUID checks). Volumetric floods of exact duplicates trigger a `Low` severity replay warning via the network sensor.
- **Sensor Failure:** If the network sensor goes completely offline, brute forces detected only on the host log still trigger `High`, fulfilling the rule. Without the network dimension, it correctly respects the ceiling constraint and avoids escalating out of bounds.

## Limitations
Because this implementation operates via inter-process `multiprocessing.Queue` architecture locally rather than a distributed message queue (e.g. Kafka, RabbitMQ) for network events, the memory footprint increases with sustained aggressive bursts of activity unless adequately scaled horizontally. For extreme velocities, packet drops at the sensor extraction phase might occur.
