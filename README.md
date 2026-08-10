# Security Log Anomaly Dashboard 

## Overview

A Python-based security log analysis designed to process authentication records and identify unusual login activity by username and IP address.

## Prerequesites 

- Python 3.10 or later
- Required libraries:

```bash
pip install pandas numpy streamlit
```
## Usage 

Now uses a Syslog listener to receive authenication logs from authorized devices 
on the network.

Supported authentication logs:

- Failed SSH logins
- Successful SSH logins

The logs covert to the following format for analysis:

- timestamp
- username
- ip_address
- status (accepts success or failed)

## Running the Dashboard

Start the Streamlit application with:
```bash
streamlit run dashboard.py
```

## Note

Project is still under development rn... 