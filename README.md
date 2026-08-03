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

Place a CSV file in the project folder with required columns (for now):

- timestamp
- username
- ip_address
- status (accepts success or failed)

## Note

Yes, some_logs.csv is in the code but it is a csv file I am testing personally for the specfic project and will not be included.

Project is still under development rn... 