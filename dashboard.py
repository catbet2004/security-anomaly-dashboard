import pandas as pd
import streamlit as st 

from analyzer import(clean_logs,ip_activity,anom_score)

from net_logs import SyslogCollector
from local_monitor import LocalLogMonitor
from device_scan import perform_device_scan

st.set_page_config(
    page_title="Security Monitor",
    layout="wide",
)

st.title("Security Monitor")
st.write("Real-time device monitoring, security event analysis, and authentication anomaly detection.")


#creates syslog collector
@st.cache_resource
def get_collector():
    collector=SyslogCollector()
    collector.start()
    return collector

collector=get_collector()

@st.cache_resource
def get_local_monitor():
    monitor=LocalLogMonitor()
    monitor.start_monitor()

    return monitor

local_monitor=get_local_monitor()

@st.cache_data(ttl=300)
def get_device_scan():
    return perform_device_scan()


st.success("● Monitoring Active")

#update every second
@st.fragment(run_every="1s")
def live_results():

    remote_logs=collector.get_logs()
    local_logs=local_monitor.return_logs()

    if not remote_logs.empty:

        remote_logs=remote_logs.copy()

        if "log_source" not in remote_logs.columns:
            remote_logs["log_source"]="remote_syslog"

    logs=pd.concat(
        [
            remote_logs,
            local_logs,
        ], 
        ignore_index=True,
    )

    total_events=0
    failed_events=0
    blocked_events=0
    suspicious_ips=0
    cleaned_logs=None
    scored_ips=None

    all_events=logs.copy()

    #count events
    if not all_events.empty:
        total_events=len(all_events)

        if "status" in all_events.columns:
            failed_events=int(
                (
                all_events["status"]=="failed"
                ).sum()
            )
            blocked_events= int(
                (
                all_events["status"]=="blocked"
                ).sum()
            )

    #auth logs go to analyzer

    auth_logs=all_events.copy()
    if "event_type" in auth_logs.columns:
        auth_logs=auth_logs[
            auth_logs["event_type"].isin(
                [
                    "ssh_login",
                    "vpn_login",
                    "windows_login",
                ]
            )
        ].copy()


#run analysis
    if not auth_logs.empty:
        try:
            cleaned_logs=clean_logs(auth_logs)
            ip_sum=ip_activity(cleaned_logs)
            scored_ips=anom_score(ip_sum)

            if ( 
                scored_ips is not None and not scored_ips.empty and "suspicious" in scored_ips.columns
            ):
                suspicious_ips=int(
                    scored_ips["suspicious"].sum()
                )
        except ValueError as error:
            st.error(str(error)
            )
    overview_tab, events_tab, threats_tab, device_tab=st.tabs(
        [
            "Overview",
            "Live Events",
            "Threat Analysis",
            "Device Security",
        ]
    )
    with overview_tab:
        st.subheader("Security Overview")
        
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

    st.subheader("Recent Threats")

    if (
        scored_ips is None or scored_ips.empty
    ):
        st.info("No authentication threats detected yet.")

    else:
        threats=scored_ips[
            scored_ips[
                "risk_level"
            ].isin(
                [
                    "High",
                    "Medium",
                ]
            )
        ]

        if threats.empty:
            st.success("No Medium or High risk authentication activity detected.")

        else:
            st.dataframe(
                threats,
                width="stretch",
            )

    #event filter

    chart1, chart2=st.columns(2)

    with chart1:
        st.subheader("Security Events by Type")

        if (
            not all_events.empty and "event_type" in all_events.columns
        ):
            event_counts=(
                all_events[
                    "event_type"
                ].value_counts().rename(
                    "Events"
                )
            )
            st.bar_chart(
                event_counts
            )
        else:
            st.info("No security events yet.")

    with chart2:
        st.subheader("Risk Level Distrbution")

        if(
            scored_ips is not None and not scored_ips.empty
        ):
            risk_counts=(
                scored_ips[
                    "risk_level"
                ].value_counts().rename("IPs")
            )

            st.bar_chart(risk_counts)

        else:
        
            st.info("No authentication risk data yet.")

    with events_tab:
        st.subheader("Live Security Events")

        st.caption("Local and remote security events received by the monitoring system.")

        if all_events.empty:
            st.info("Waiting for security events...")

        else:
            filtered_events=(all_events.copy())

            filter1, filter2= st.columbs(2)

            with filter1:
                if(
                    "event_type" in filtered_events.columns
                ):
                    available_event_types=(
                        filtered_events[
                            "event_type"
                        ].dropna().unique().tolist()
                    )

                    selected_event_types=st.multiselect(
                        "Event Type",
                        available_event_types,
                        default=available_event_types,
                        key="event_type_filter",
                    )
                    filtered_events=filtered_events[
                        filtered_events[
                            "event_type"
                        ].isin(selected_event_types)
                    ]

            with filter2:
                if("status" in filtered_events.columns):
                    available_statuses=(
                        filtered_events[
                            "status"
                        ].dropna().unique().tolist()
                    )

                    selected_statuses=st.multiselect(
                        "Status",
                        available_statuses,
                        default=available_statuses,
                        key="status_filter",
                    )
                    filtered_events=filtered_events[
                        filtered_events[
                            "status"
                        ].isin(selected_statuses)
                    ]
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
                    width="stretch",
                )

                st.caption(
                    f"Showing {len(filtered_events)} of {len(all_events)} events." 
                )

    with threats_tab:
        st.subheader("Authentication Threat Analysis")

        st.caption("Detects unusual authentication behavior including brute force, password spraying, rapid failures, and off-hours activity.")

        if(
            cleaned_logs is None
            or cleaned_logs.empty
            or scored_ips is None
            or scored_ips.empty
        ):
            st.info("No authentication events available for analysis yet.")

        else:


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
                key="risk_filter",
            )
            filtered_ips=scored_ips[
                scored_ips[
                    "risk_level"
                ].isin(risk_filter)
            ]

            st.subheader("IP Security Analysis")

            st.dataframe(filtered_ips, width="stretch")

            st.divider()

            chart1,chart2=st.columns(2)

            with chart1:
                st.subheader("Failed Logins Over Time")

                failed_logs=cleaned_logs[
                    cleaned_logs[
                        "status"
                    ]=="failed"
                ].copy()

                if not failed_logs.empty:
                    failed_over_time=(
                        failed_logs
                        .set_index(
                            "timestamp"
                        ).resample(
                            "5min"
                        ).size()
                        .rename(
                        "Failed Logins"
                        )
                    )

                    st.line_chart(failed_over_time)

                else:
                    st.info("No failed login events yet.")

            with chart2:
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

            st.subheader("Invesitgate IP Address")

            ip_options=(
                scored_ips["ip_address"].dropna().unique().tolist()
            )

            if ip_options:
                selected_ip=st.selectbox(
                    "Select an IP address",
                    ip_options,
                    key="investigate_ip",
                )

                ip_details=scored_ips[
                    scored_ips["ip_address"]==selected_ip
                ]
                st.write("**IP Risk Summary**")
                st.dataframe(ip_details, width="stretch")

                st.write("**Security Event History**")

                if(
                    not all_events.empty and "ip_address" in all_events.columns
                ):
                    ip_events=all_events[
                        all_events[
                            "ip_address"
                        ]==selected_ip
                    ].copy()

                    if (
                        "timestamp" in ip_events.columns
                    ):
                        ip_events=(
                            ip_events.sort_values(
                                "timestamp",
                                ascending=False,
                            )
                        )
                    st.dataframe(ip_events, width="strecth")

    with device_tab:

        st.subheader("Device Security")

        st.caption("Scans the computer for configured TCP ports and exposed services.")

        if st.button(
            "Run Device Scan",
            key="run_device_scan",
        ):
            #clear result so scan runs again
            get_device_scan.clear()

        try:
            (
                devices,
                local_ip,
                interface,
            )=get_device_scan()

            needs_review=False

            if(not devices.empty and "attention" in devices.columns):
                needs_review=(
                    devices[
                        "attention"
                    ]=="Review"
                ).any()

            if needs_review:
                device_status=("Review")

            else:
                device_status=("Normal")

            col1, col2, col3=st.columns(3)

            with col1:
                st.metric("Device IP", local_ip)

            with col2:
                st.metric("Network Interface", interface)

            with col3:
                st.metric("Device Status", device_status)

            st.divider()

            st.subheader("Open Services")

            st.dataframe(devices, width="stretch")

            if(not devices.empty and "attention" in devices.columns):

                review_devices=devices[
                    devices[
                        "attention"
                    ]=="Review"
                ]

                if review_devices.empty:
                    st.success("No configured services requiring review were detected.")

                else:
                    st.warning("One or more exposed services may need review.")

                    st.dataframe(
                        review_devices,
                        width="stretch",
                    )

            st.caption("Note: An open port does not mean your device is vulnerable. The scan only checks for ports and services currently configured in the scanner.")

        except(
            RuntimeError,
            OSError,
        ) as error:

            st.warning(f"Device scan unavailable: {error}")

live_results()



    


        


