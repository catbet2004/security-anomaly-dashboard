import time
from alert_engine import(generate_alerts, store_generated_alerts)
from store_events import (get_security_events, get_security_events_after_id, get_recent_events, get_last_event_id, save_last_event_id)

CHECK_INTERVAL=5
LOOKBACK_MINUTES=10

def run_analysis_worker():
    print("Security analysis worker started.")

    saved_event_id=(get_last_event_id())

    if saved_event_id is None:
        

        exisiting_events=get_security_events()

        if exisiting_events.empty:
            last_event_id=0

        else:
            last_event_id=int(exisiting_events["id"].max())

        save_last_event_id(last_event_id)

    else:
        last_event_id=(saved_event_id)

    print(f"Starting after event ID: "
          f"{last_event_id}")

    while True:
        try:
            new_events=(get_security_events_after_id(last_event_id))

            if new_events.empty:
                time.sleep(CHECK_INTERVAL)
                continue

            print(f"\nFound "
                  f"{len(new_events)} "
                  f"new security event(s).")

            newest_event_id=int(new_events["id"].max())

            recent_events=(get_recent_events(LOOKBACK_MINUTES))

            print(f"Analyzing "
                  f"{len(recent_events)}"
                  f" recent event(s).")

            alerts=generate_alerts(recent_events)

            if alerts.empty:
                print("No threats detected.")

            else:
                print(f"{len(alerts)} "
                      f"alert(s) detected.")

                store_generated_alerts(alerts)

            last_event_id=(newest_event_id)

            save_last_event_id(last_event_id)

    
        except KeyboardInterrupt:
            print("\nSecurity analysis worker stopped.")

            break

        except Exception as error:
            print(f"Analysis worker error: "
                f"{error}")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":

    run_analysis_worker()