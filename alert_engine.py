import pandas as pd
from analyzer import(clean_logs,ip_activity,anom_score)
from firewall_analysis import(analyze_firewall_activity)
from web_threats import(analyze_web_activity)
from store_events import (get_security_events, get_security_alerts, save_or_update_alert)

def create_auth_alerts(logs:pd.DataFrame)->list[dict]:

    alerts=[]

    if logs.empty:
        return alerts

    auth_logs=logs.copy()

    if "event_type" not in auth_logs.columns:
        return alerts

    auth_event_types=[
        "ssh_login",
        "vpn_login",
        "windows_login",
    ]

    auth_logs=auth_logs[
        auth_logs["event_type"].isin(auth_event_types)
    ]

    if auth_logs.empty:
        return alerts

    try:
        cleaned=clean_logs(auth_logs)
        activity=ip_activity(cleaned)
        results=anom_score(activity)

    except ValueError:
        return alerts

    for _, row in results.iterrows():
        risk_level=row.get("risk_level", "Low")


        ip_address=row.get("ip_address", "unknown")

        brute_force=row.get("brute_force_potential", False)

        password_spray=row.get("password_spray_potential", False)


        #scoring

        if brute_force:
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "High",
                    "category": "Authentication",
                    "title": "Possible Brute-Force Attack",
                    "ip_address": ip_address,
                    "description":
                    (
                        "Rapid failed login attempts were detected from this IP."
                    ),

                    "risk_score": max(
                        row.get("anomaly_score",0),3.0)
                }
            )

        if password_spray:
            alerts.append(
                {
                    "timestamp":pd.Timestamp.now(),

                    "severity": "High",
                    "category": "Authentication",
                    "title": "Possible Password Spray",
                    "ip_address": ip_address,
                    "description":
                    (
                        "Failed authentication attempts were detected across multiple users."

                    ),
                    "risk_score":
                        row.get("anomaly_score", 0),

                }
            )

        if (not brute_force and not password_spray and risk_level !="Low"):

            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": risk_level,
                    "category":"Authentication",
                    "title":"Unusual Authentication Activity",
                    "ip_address": ip_address,
                    "description":
                    (
                        "Authentication behavior exceeded the configured anomaly threshold."
                    ),

                    "risk_score":
                        row.get("anomaly_score", 0),

                }
            )

    return alerts

#firewall

def create_firewall_alerts(logs:pd.DataFrame)->list[dict]:

    alerts=[]

    results=analyze_firewall_activity(logs)

    if results.empty:
        return alerts

    for _, row in results.iterrows():

        ip_address=row.get("ip_address", "unknown")

        #port scan
        if row.get("possible_port_scan", False):
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "High",
                    "category": "Firewall",
                    "title": "Possible Port Scan",
                    "ip_address": ip_address,
                    "description":
                    (
                        f"{row.get('unique_ports', 0)} different ports were targeted."
                    ),

                    "risk_score": 3.0,
                    

                }
            )
        #repeated firewall blocks

        elif row.get("repeated_blocks", False):
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "Medium",
                    "category": "Firewall",
                    "title": "Repeated Blocked Connections",
                    "ip_address": ip_address,
                    "description":
                        (
                            f"{row.get('max_blocks_5min',0)} blocked connections occured within five minutes."

                        ),

                    "risk_score": 2.0,

                }

            )

        #port targeting
        sensitive_ports=row.get("sensitive_ports", [])

        if sensitive_ports:
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "Medium",
                    "category": "Firewall",
                    "title":"Sensitive Service Targeted",
                    "ip_address":ip_address,
                    "description":
                        (
                            "Traffic targeted sensitive ports: " 
                            f"{sensitive_ports}"

                        ),
                    "risk_score": 2.0,
                }
            )

    return alerts

def create_web_alerts(logs: pd.DataFrame)->list[dict]:
    alerts=[]

    results=analyze_web_activity(logs)

    if results.empty:
        return alerts

    for _, row in results.iterrows():
        ip_address=row.get("ip_address", "unknown")

    #auth probing

        if row.get("possible_auth_probe", False):

            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "High",
                    "category": "Web",
                    "title": "Possible Web Authentication Probe",
                    "ip_address":ip_address,
                    "description":
                        (
                            f"{row.get('max_failed_5min', 0)} failed web authentication requests occurred within five minutes."


                        ),
                    "risk_score": 3.0,

                }
            )

        #sensitive path probing

        if row.get("possible_path_probe", False):
            alerts.append(
                {
                    "timestamp":pd.Timestamp.now(),
                    "severity": "High",
                    "category": "Web",
                    "title": "Sensitive Web Paths Probed",
                    "ip_address": ip_address,
                    "description":
                        (
                            "Requests targeted sensitive paths: "
                            f"{row.get('sensitive_paths', [])}"

                        ),
                    "risk_score": 3.0,

                }
            )

    #404 scan

        if row.get("possible_404_scan", False):
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "Medium",
                    "category": "Web",
                    "title": "Possible Web Path Scan",
                    "ip_address": ip_address,
                    "description":
                        (
                            f"{row.get('not_found_requests', 0)} "
                            "HTTP 404 responses were generated across multiple paths."

                        ),
                    "risk_score": 2.0,

                }
            )

        #request rate

        if row.get("high_request_rate", False):
            alerts.append(
                {
                    "timestamp": pd.Timestamp.now(),
                    "severity": "Medium",
                    "category": "Web",
                    "title": "High Web Request Rate",
                    "ip_address": ip_address,
                    "description":
                        (
                            f"{row.get('max_requests_1min',0)} "
                            "requests were observed within one minute."

                        ),
                    "risk_score": 2.0,
                }
            )

    return alerts

#combine and configure alerts

def generate_alerts(logs:pd.DataFrame)-> pd.DataFrame:

    alerts=[]

    alerts.extend(create_auth_alerts(logs))

    alerts.extend(create_firewall_alerts(logs))

    alerts.extend(create_web_alerts(logs))

    if not alerts:
        return pd.DataFrame(
            columns=[
                "timestamp",
                "severity",
                "category",
                "title",
                "ip_address",
                "description",
                "risk_score",
            ]
        )
    alert_df=pd.DataFrame(alerts)

    #high severity first

    severity_order={
        "High": 3, "Medium": 2, "Low": 1
    }

    alert_df["severity_rank"]=alert_df["severity"].map(severity_order)

    alert_df=alert_df.sort_values(
        [
            "severity_rank",
            "risk_score",
        ],
        ascending=[
            False,
            False,
        ],
    )

    alert_df=alert_df.drop(columns=["severity_rank"])

    return alert_df.reset_index(drop=True)

def store_generated_alerts(alerts: pd.DataFrame):

    if alerts.empty:
            print("No alerts to store.")
            return

    for _, row in alerts.iterrows():

        alert=row.to_dict()

        result=save_or_update_alert(alert)

        title=alert.get("title", "Unknown Alert")

        ip_address=alert.get("ip_address", "unknown")

        if result == "inserted":
            print(f"New alert saved: "
                    f"{title} - {ip_address}")

        elif result == "updated":
            print(f"Existing alert updated: "
                    f"{title} - {ip_address}")







