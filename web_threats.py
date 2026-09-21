import json
import pandas as pd

SENSITIVE_PATHS={
    "/admin",
    "/login",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/.git",
    "/config",
    "/backup",
}

def expand_event_data(logs: pd.DataFrame) -> pd.DataFrame:
    expanded = logs.copy()

    if("event_data" not in expanded.columns):
        return expanded

    def parse_data(value):
        if not value:
            return {}
        if isinstance(value,dict):
            return value
        try:
            return json.loads(value)

        except(json.JSONDecodeError, TypeError):
            return {}

    event_details=(expanded["event_data"].apply(parse_data).apply(pd.Series))

    #avoid duplicate cols

    for column in event_details.columns:
        if column not in expanded.columns:
            expanded[column]=(event_details[column])

    return expanded

def clean_web_logs(logs:pd.DataFrame)->pd.DataFrame:
    web_logs=logs.copy()

    if web_logs.empty:
        return web_logs

    if "event_type" in web_logs.columns:

        web_logs=web_logs[web_logs["event_type"]=="web_request"].copy()

    if web_logs.empty:
        return web_logs

    #recover from SQLite JSON

    web_logs=expand_event_data(web_logs)

    web_logs["timestamp"]=pd.to_datetime(web_logs["timestamp"], errors="coerce")

    web_logs=web_logs.dropna(subset=["timestamp", "ip_address"])

    if("status_code" in web_logs.columns):
        web_logs["status_code"]=pd.to_numeric(
            web_logs["status_code"], errors="coerce",
        )

    return web_logs.reset_index(drop=True)


def analyze_web_activity (logs:pd.DataFrame)->pd.DataFrame:
    web_logs=clean_web_logs(logs)

    if web_logs.empty:
        return pd.DataFrame()

    results=[]

    for ip_address, group in(web_logs.groupby("ip_address")):
        group=group.sort_values("timestamp")

        total_requests=len(group)

        failed_auth_requests=0
        not_found_requests=0

        if("status_code" in group.columns):
            failed_auth_requests=int(
                group["status_code"].isin(
                    [401, 403]
                ).sum()
            )

            not_found_requests=int((group["status_code"]==404).sum())

        request_series=pd.Series(1,index=group["timestamp"], dtype=int)

        requests_1min=(request_series.rolling("1min").sum())

        max_requests_1min=(int(requests_1min.max()))


        auth_failures=group[group["status_code"].isin([401,403])].copy()

        if not auth_failures.empty:
            auth_series=pd.Series(1, index=auth_failures["timestamp"],dtype=int)

            failed_5min=(auth_series.rolling("5min").sum())

            max_failed_5min=int(failed_5min.max())

        else:
            max_failed_5min=0


        if "path" in group.columns:
            unique_paths=int(group["path"].dropna().nunique())

        else:
            unique_paths=0

        sensitive_paths=[]

        if "path" in group.columns:
            requested_paths=(group["path"].dropna().astype(str).tolist())

            for path in requested_paths:

                clean_path=(path.split("?")[0].lower())

                if clean_path in SENSITIVE_PATHS:
                    if(clean_path not in sensitive_paths):
                        sensitive_paths.append(clean_path)

            possible_auth_probe=(max_failed_5min>=5)

            possible_path_probe=(len(sensitive_paths)>=2)

            possible_404_scan=(not_found_requests>=10 and unique_paths>=10)

            high_request_rate=(max_requests_1min>=60)


            results.append(
                {
                    "ip_address": ip_address,
                    "total_requests": total_requests,
                    "failed_auth_requests": failed_auth_requests,
                    "not_found_requests": not_found_requests,
                    "unique_paths":unique_paths,
                    "max_requests_1min": max_requests_1min,
                    "max_failed_5min":max_failed_5min,
                    "sensitive_paths":sensitive_paths,
                    "possible_auth_probe":possible_auth_probe,
                    "possible_404_scan":possible_404_scan,
                    "high_request_rate": high_request_rate,

                }
            )

    return pd.DataFrame(results)
