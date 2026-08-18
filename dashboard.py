import streamlit as st
from analyzer import anom_score, clean_logs, ip_activity
from net_logs import SyslogCollector

st.set_page_config(
    page_title="Security Log Anomaly Dashboard",
    layout="wide",
)

st.title("Security Log Anomaly Dashboard")
st.write("Live authentication and anomaly detection for SSH, VPN, firewall, and web activity.")


#creates syslog collector
@st.cache_resource
def get_collector():
    collector=SyslogCollector()
    collector.start()
    return collector

collector=get_collector()

st.success("Live Syslog monitoring is running on UDP port 5514.")

#update every second
@st.fragment(run_every="1s")
def live_results():
    logs=collector.get_logs()

    if logs.empty:
        st.info("Waiting for security logs...")
        return
    
    all_events=logs.copy()


    #count events

    total_events=len(all_events)
    failed_events=0
    if "status" in all_events.columns:
        failed_events=(
            all_events["status"]=="failed"
        ).sum()

    blocked_events=0

    if "status" in all_events.columns:
        blocked_events=(
            all_events["status"]=="blocked"
        ).sum()

    #auth logs go to analyzer

    auth_logs=all_events.copy()
    if "event_type" in auth_logs.columns:
        auth_logs=auth_logs[
            auth_logs["event_type"].isin(
                [
                    "ssh_login",
                    "vpn_login",
                ]
            )
        ].copy()
#defaults if no logs
    cleaned_logs=None
    scored_ips=None
    suspicious_ips=0

#run analysis
    if not auth_logs.empty:
        try:
            cleaned_logs=clean_logs(auth_logs)
            ip_sum=ip_activity(cleaned_logs)
            scored_ips=anom_score(ip_sum)

            if not scored_ips.empty:
                suspicious_ips=int(
                    scored_ips[
                        "suspicious"
                    ].sum()
                )
        except ValueError as error:
            st.error(str(error))
            return
        
    col1,col2,col3,col4=st.columns(4)

    with col1:
        st.metric("Security Events", total_events)

    with col2:
        st.metric("Failed Events", int(failed_events))

    with col3:
        st.metric("Blocked Connections", int(blocked_events))

    with col4:
        st.metric("Suspicious IPs", suspicious_ips)

    st.divider()

    #event filter

    st.subheader("Security Event Filters")

    if "event_type" in all_events.columns:
        available_event_types=(
            all_events["event_type"].dropna().unique().tolist()
        )
        selected_event_types=st.multiselect(
            "Event Type",
            available_event_types,
            default=available_event_types,
        )
        filtered_events=all_events[
            all_events["event_type"].isin(
                selected_event_types
            )
        ]
    else:
        filtered_events=all_events

    #status filter

    if "status" in filtered_events.columns:
        available_statuses=(
            filtered_events["status"].dropna().unique().tolist()
        )
        selected_statuses=st.multiselect(
            "Status",
            available_statuses,
            default=available_statuses,
        )
        filtered_events=filtered_events[
            filtered_events["status"].isin(
                selected_statuses
            )
        ]
    st.subheader("Live Security Events")

    if(
        "timestamp" in filtered_events.columns
    ):
        filtered_events=(
            filtered_events.sort_values(
                "timestamp",
                ascending=False,
            )
        )
    st.dataframe(
        filtered_events, 
        width="stretch"
    )

    st.divider()

    if "event_type" in all_events.columns:
        st.subheader("Security Events by Type")

        event_counts=(
            all_events["event_type"].value_counts().rename("events")
        )
        st.bar_chart(event_counts)

    #stop if no events
    if(
        cleaned_logs is None
        or cleaned_logs.empty
        or scored_ips is None
        or scored_ips.empty
    ):
        st.info("No SSH or VPN authentication events available for analysis yet.")
        return
    
    st.divider()

    st.subheader("Authentication Risk Analysis")

    risk_filter=st.multiselect(
        "Risk Level",
        [
            "High",
            "Medium",
            "Low",
        ],
        default=[
            "High",
            "Medium",
            "Low",
        ],
    )
    filtered_ips=scored_ips[
        scored_ips[
            "risk_level"
        ].isin(risk_filter)
    ]

    st.subheader("IP Security Analysis")

    st.dataframe(filtered_ips, width="stretch")

    st.subheader("Risk Level Distribution")

    risk_counts=(
        scored_ips["risk_level"].value_counts().rename("IPs")

    )
    st.bar_chart(risk_counts)


    st.subheader("Failed Logins")

    failed_logs=cleaned_logs[
        cleaned_logs["status"]=="failed"
    ].copy()

    if not failed_logs.empty:
        failed_over_time=(
            failed_logs.set_index("timestamp").resample("5min").size().rename("Failed Logins")
        )
        st.line_chart(failed_over_time)
    else:
        st.info("No failed login events yet.")

    st.subheader("Most Suspicious IP Addresses")

    top_ips=(
        scored_ips[
            [
                "ip_address",
                "anomaly_score",
            ]
        ].head(10).set_index("ip_address")
    )
    st.bar_chart(top_ips)
    st.divider()

    st.subheader("Investigate IP Address")

    ip_options=(
        scored_ips["ip_address"].dropna().unique()
    )

    selected_ip=st.selectbox("Select an IP address", ip_options)

    ip_details=scored_ips[
        scored_ips["ip_address"]==selected_ip
    ]
    st.write("IP Risk Summary")

    st.dataframe(ip_details, width="stretch")

    #all events from ip

    ip_events=all_events[
        all_events["ip_address"]==selected_ip
    ].copy()

    if "timestamp" in ip_events.columns:
        ip_events=(
            ip_events.sort_values(
                "timestamp",
                ascending=False,
            )
        )
    st.write("Security Event History")

    st.dataframe(ip_events, width="stretch")

live_results()


        


