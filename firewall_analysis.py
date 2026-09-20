import pandas as pd

SENSITIVE_PORTS={
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}

def clean_firewall_logs(logs:pd.DataFrame)-> pd.DataFrame:
    firewall_logs=logs.copy()

    if firewall_logs.empty:
        return firewall_logs

    if "event_type" in firewall_logs.columns:

        firewall_logs=firewall_logs[firewall_logs["event_type"]=="firewall_block"].copy()

        if firewall_logs.empty:
            return firewall_logs

        #convert timestamps
        firewall_logs["timestamp"]=(pd.to_datetime(firewall_logs["timestamp"], errors="coerce"))

        #remove events w/ no timestamp
        firewall_logs=firewall_logs.dropna(
            subset=["timestamp", "ip_address"]
        )

        #port to numeric
        if "destination_port" in firewall_logs.columns:
            firewall_logs["destination_port"]= pd.to_numeric(
                firewall_logs["destination_port"], errors="coerce",
            )
        return firewall_logs.reset_index(drop=True)

def analyze_firewall_activity(logs:pd.DataFrame)-> pd.DataFrame:
    firewall_logs=clean_firewall_logs(logs)

    if firewall_logs.empty:
        return pd.DataFrame()

    results=[]

    for ip_address, group in (
        firewall_logs.groupby("ip_address")
    ):
        group=group.sort_values("timestamp")

        total_blocks=len(group)

        #unique ports

        if "destination_port" in group.columns:
            unique_ports=int(group["destination_port"].dropna().nunique())

        else:
            unique_ports=0

        #rapid blocks

        indexed=(group.set_index("timestamp").sort_index())

        rapid_blocks=(indexed.rolling("5min").size())

        max_blocks_5min=int(rapid_blocks.max())

        possible_port_scan=(unique_ports>=10 and max_blocks_5min>=20)

        repeated_blocks=(max_blocks_5min>=10)

        sensitive_ports=[]

        if "destination_port" in group.columns:

            for port in(group["destination_port"].dropna().unique()):

                port=int(port)

                if port in SENSITIVE_PORTS:
                    sensitive_ports.append(port)

        results.append(
            {
                "ip_address": ip_address,
                "total_blocks": total_blocks,
                "unique_ports": unique_ports,
                "max_blocks_5min": max_blocks_5min,
                "possible_port_scan": possible_port_scan,
                "repeated_blocks": repeated_blocks,
                "sensitive_ports": sensitive_ports,

            }
        )
    return pd.DataFrame(results)

