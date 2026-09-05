import json
import platform
import subprocess
import threading
import time
import pandas as pd
from net_logs import auth_log

class LocalLogMonitor:
    def __init__(self):
        self.events=[]
        self.lock=threading.Lock()
        self.running=False
        self.process=None

        #same event not repeatedly recorded (Windows only)
        self.seen_by_windows=set()

    def start_monitor(self):
        if self.running:
            return
        self.running=True
        listener=threading.Thread(target=self.listen, daemon=True)

        listener.start()

    def listen(self):
        system=platform.system()

        print(f"Local security monitoring started for {system}.")

        if system=="Darwin":
            self.listen_macos()

        elif system=="Linux":
            self.listen_linux()

        elif system=="Windows":
            self.listen_windows()

        else:
            print(f"Local log monitoring is not supported for {system}.")

    def save_event(self, event: dict):
        event["log_source"]="local"

        with self.lock:
            self.events.append(event)

    def log_message(self, message:str):
        event=auth_log(message, "127.0.0.1")
        if event is not None:
            self.save_event(event)

            print("Local security event recorded.")

    def listen_macos(self):
        print("Monitoring local MacOS SSH activity...")

        command=[
            "/usr/bin/log",
            "stream",
            "--style",
            "syslog",
            "--predicate",
            'process=="sshd"',
        ]

        try:
            self.process=subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            if self.process.stdout is None:
                return

            for line in self.process.stdout:
                if not self.running:
                    break

                message=line.strip()

                if not message:
                    continue

                self.log_message(message)

        except OSError as error:
            print(f"MacOS log monitoring error: {error}")    

    def monitor_linux(self):
        print("Monitoring local Linux SSH activity...")

        command=[
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "cat",
            "_COMM=sshd",
        ]

        try:
            self.process=subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bifsize=1,
            )

            if self.process.stdout is None:
                return
            for line in self.process.stdout:
                if not self.running:
                    break

                message=line.strip()

                if not message:
                    continue

                self.log_message(message)

        except FileNotFoundError:
            self.monitor_linux_auth_file()

        except OSError as error:
            print(f"Linux log monitoring error: {error}")

    #backup case for linux
    def monitor_linux_auth_file(self):
        print("journalctl unavailable. Trying /var/log/auth.log...")

        command=[
            "tail",
            "-F",
            "/var/log/auth.log",
        ]

        try:
            self.process=subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )

            if self.process.stdout is None:
                return

            for line in self.process.stdout:

                if not self.running:
                    break

                message=line.strip()

                if not message:
                    continue

                self.log_message(message)
        except OSError as error:
            print(f"Linux auth log error: {error}")

    def monitor_windows(self):
        print("Monitoring Windows Security events...")

        while self.running:
            try:
                events=(self.get_windows_events())

                for event in events:

                    record_id=event.get("RecordId")

                    if(record_id in self.seen_windows_records):
                        continue

                    self.seen_by_windows.add(record_id)

                    event_id=event.get("Id")

                    username=event.get("TargetUserName")

                    ip_address=event.get("IpAddress")

                    #ignore console logins with no remote IP

                    if(
                        not ip_address or ip_address in
                        [
                            "-",
                            "::1",
                            "127.0.0.1",
                        ]

                    ):
                        continue

                    if event_id==4624:
                        status="success"
                    elif event_id==4625:
                        status="failed"
                    else:
                        continue

                    normalized_event={
                        "timestamp":pd.Timestamp.now(),
                        "username": username
                        or "unknown",
                        "ip_address": ip_address,
                        "status": status,
                        "event_type":"windows_login",
                        "source_ip":"127.0.0.1",
                    }

                    self.save_event(normalized_event)

            except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:

                print(f"Windows monitoring error: {error}")

            time.sleep(2)

    def windows_events(self)->list[dict]:

        powershell_script=r"""
$events=Get-WinEvent `
    -FilterHashtable @{
        LogName='Security';
        Id=4624, 4625
    } `
    -MaxEvents 25 `
    -ErrorAction SilentlyContinue
foreach($event in $events){
    $xml=[xml]$evemt.ToXml()
    $values=@{}
    
    foreach ($item in $xml.Evemt.EventData.Data){
        $values[$item.Name]=$item. '#text'
    }
    [PSCustomObject]@{
        RecordId        =$event.RecordId
        Id              =$event.Id
        TargetUserName  =$values['TargetUserName]
        IpAddress       =$values['IpAddress]
    } | ConvertTo-Json -Compress
}
"""
        result=subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                powershell_script,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        events=[]

        for line in result.stdout.splitlines():
            line=line.strip()

            if not line:
                continue

            events.append(json.loads(line))

        return events

    def return_logs(self)->pd.DataFrame:
        with self.lock:
            event_copy=(self.events.copy())
        return pd.DataFrame(event_copy)

    def stop_run(self):
        self.running=False
        if self.process is not None:

            try:
                self.process.terminate()

            except OSError:
                pass

if __name__ == "__main__":

    monitor = LocalLogMonitor()

    monitor.start_monitor()

    print(
        "Local collector started."
    )

    try:

        while True:

            print(
                "\nCurrent local events:"
            )

            print(
                monitor.return_logs()
            )

            time.sleep(5)

    except KeyboardInterrupt:

        monitor.stop_run()

        print(
            "\nLocal collector stopped."
        )