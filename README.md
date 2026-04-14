# Firewall Traffic Analysis

## Description
This project analyzes firewall traffic logs and performs NAT audit using Python.

## Features
- Analysis of ALLOW / DENY traffic
- Detection of high-risk ports (e.g. 4444, 6667, 9050)
- Identification of suspicious IP activity
- NAT audit (DNAT / SNAT analysis)
- Detection of potential internal IP leaks
- Traffic visualization using charts

## Technologies
- Python
- Pandas
- Matplotlib
- Seaborn

## How it works
- Reads firewall logs from CSV file
- Groups traffic by hour and action
- Detects unusual patterns in network activity
- Identifies risky open ports and abnormal traffic
- Generates charts for visual analysis

## Output
- Top source IPs
- Top destination ports
- High-risk traffic alerts
- Traffic charts (saved in /charts folder)

## Project Goal
To demonstrate basic firewall log analysis and network security monitoring.
