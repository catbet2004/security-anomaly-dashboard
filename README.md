# Security Log Anomaly Dashboard 

## Overview

A Python-based security log analysis designed to process authentication records and identify unusual login activity by username and IP address.

## Prerequesites 

- Python 3.10 or later
- macOS, Linux, or Windows
- Required Python libraries:

```bash
pip install pandas numpy streamlit psutil
```

## Current Features (more to come)

### Security Event Monitoring

- Live Syslog listener on UDP port 5514
- Automatic local operating system log monitoring
- Local and remote SSH authentication monitoring
- VPN authentication and connection event monitoring
- VPN event monitoring
- Firewall blocked connection monitoring
- Web request monitoring

### Authentication Threat Detection

- Brute-force detection
- Password-spraying detection
- Rapid failed-login detection
- Off-hours authentication tracking
- Anomaly scoring by IP address
- Low, Medium, High risk levels

### Device Security Scanning

- Detects the active network interface
- Detects the device's local IP address
- Scans common TCP ports
- Identifies exposed services
- Flags selected services that may need review

## Supported Local Monitoring

### MacOS

- SSH authentication activity
- macOS firewall activity
- VPN/Network Extension activity
- Local Apache or Nginx web access logs when available

### Linux

- SSH authentication activity
- Firewall activity from system logs
- VPN-related system events
- Apache or Nginx web access logs when available

### Windows

- Successful and failed Windows login events
- Windows firewall blocked connection events
- Windows VPN events
- IIS web access logs when available

## Running the Dashboard

Start the Streamlit application with:
```bash
streamlit run dashboard.py
```

## Notes

- Streamlit is temporary, will be implementing a more accessible frontend later

- Long-term goal is to develop this project into a lightweight endpoint security application that can run in the background on a user's computer and provide real-time security monitoring and alerts.

- Project is still in progress...

