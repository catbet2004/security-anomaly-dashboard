import streamlit as st 

from analyzer import(clean_logs,ip_activity,anom_score)

from net_logs import SyslogCollector

st.set_page_config(
    page_title="Security Log Anomaly Dashboard",
    layout="wide",
)

st.title("Security Log Anomaly Dashboard")

st.write("Live authentication and anomaly detection.")

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
        st.info("Waiting for authentication logs...")
        return
    try:

        cleaned_logs=clean_logs(logs)

        ip_sum=ip_activity(cleaned_logs)

        scored_ips=anom_score(ip_sum)

    except ValueError as error:
        st.error(str(error))
        return

    failed_attempts=(cleaned_logs["status"]=="failed").sum()
    sus_ips=scored_ips["suspicious"].sum()

    #dashboard boxes
    col1,col2,col3=st.columns(3)

    with col1:
        st.metric("Authentication Events",len(cleaned_logs))

    with col2:
        st.metric("Failed logins",int(failed_attempts))

    with col3:
        st.metric("Suspicious IPs",int(sus_ips))

    st.subheader("IP Security Analysis")
    st.dataframe(scored_ips,use_container_width=True)

    st.subheader("Authentication Events")
    st.dataframe(cleaned_logs, use_container_width=True)

live_results()

    

