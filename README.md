# Security Log Anomaly Dashboard 

## Overview

A Python-based security log analysis designed to process authentication records and identify unusual login activity by username and IP address.

## Prerequesites 

- Python 3.10 or later
- Required libraries:

```bash
pip install pandas numpy streamlit
```

## Current Features (more to come)

- Live Syslog listener on UDP port 5514
- SSH login monitoring
- VPN login monitoring
- Firewall event monitoring
- Web request monitoring
- Failed and successful login detection
- Brute-force detection
- Password-spraying detection
- Rapid login attempt detection
- Off-hours activity tracking
- Anomaly scoring by IP 
- Low, Medium, High risk levels
- Live event filtering and security charts 
- IP investigation and event history 

The logs covert to the following format for analysis:

- timestamp
- username
- ip_address
- status (accepts success or failed)
- event_type
- source_ip

## Running the Dashboard

Start the Streamlit application with:
```bash
streamlit run dashboard.py
```

## Note

Project is still under development rn... 



