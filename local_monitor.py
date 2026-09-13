import glob
import re
import os
import json
import platform
import subprocess
import threading
import time
import pandas as pd
from net_logs import auth_log
from store_events import save_security_event

class LocalLogMonitor:
    def __init__(self):
        self.events=[]
        self.lock=threading.Lock()
        self.running=False
        self.processes=[]
        self.monitor_threads=[]

        #same event not repeatedly recorded (Windows only)
        self.seen_by_windows=set()
        self.seen_windows_vpn=set()

    def start_monitor(self):
        if self.running:
            return
        self.running=True
        self.listen()

    def listen(self):
        system=platform.system()

        print(f"Local security monitoring started for {system}.")

        monitors=[]

        if system=="Darwin":

            monitors=[
                self.listen_macos,
                self.macos_firewall,
                self.macos_vpn,
                self.macos_web,
            ]
        elif system=="Linux":
            monitors=[
                self.monitor_linux,
                self.linux_firewall,
                self.linux_vpn,
                self.linux_web,
            ]

        elif system=="Windows":
            monitors=[
                self.monitor_windows,
                self.windows_web,
                self.windows_vpn,
            ]

        else:
            print(f"Local log monitoring is not supported for {system}.")

            return

        for monitor in monitors:
            thread=threading.Thread(
                target=monitor,
                daemon=True,
            )
            thread.start()

            self.monitor_threads.append(thread)

    def save_event(self, event: dict):
        event.setdefault(
            "timestamp",
            pd.Timestamp.now(),
        )
        event["log_source"]="local"

        with self.lock:
            self.events.append(event)

        save_security_event(event)

    def stream_command(self, command:list[str], handler, name:str):
        try:
            process=subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            self.processes.append(process)

            if process.stdout is None:
                return
            for line in process.stdout:
                if not self.running:
                    break

                message=line.strip()

                if not message:
                    continue

                handler(message)

        except FileNotFoundError:
            print(f"{name} unavailable.")

        except OSError as error:
            print(f"{name} error: {error}")

    def log_message(self, message:str):
        event=auth_log(message, "127.0.0.1")
        if event is not None:
            self.save_event(event)

            print("Local security event recorded.")

    def parse_firewall(self,message:str):
        lower_message=(message.lower())

        firewall_keywords=[
            "block",
            "blocked",
            "deny",
            "denied",
            "drop",
            "dropped",
        ]

        if not any(
            keyword in lower_message for keyword in firewall_keywords 
        ):
            return

        ip_match=re.search(
            r"\bSRC="
            r"(?P<ip>\d{1,3}"
            r"(?:\.\d{1,3})({3})",
            message,
            re.IGNORECASE,
        )

        if ip_match is None:
            ip_match=re.search(
                r"\bfrom\s+"
                r"(?P<ip>\d{1,3}"
                r"(?:\.d{1,3})({3})",
                message,
                re.IGNORECASE,
            )
        if ip_match is None:
            ip_match=re.search(
                r"(?P<ip>\d{1,3}"
                r"(?:\.\d{1,3})({3})",
                message,
            )
        if ip_match is not None:
            ip_address=(ip_match.group("ip"))

        else:
            ip_address="unknown"

        #try to get destiniation port
        port_match=re.search(
            r"\b(?:DPT|DSTPORT)"
            r"[=:]"
            r"(?P<port>\d+)",
            message,
            re.IGNORECASE,
        )

        destination_port=None

        if port_match is not None:
            destination_port=int(port_match.group("port"))

        event={
            "timestamp":
                pd.Timestamp.now(),

            "username":
                "unknown",

            "ip_address":
                ip_address,

            "status":
                "blocked",

            "event_type":
                "firewall_block",

            "destination_port":
                destination_port,

            "source_ip":
                "127.0.0.1",

            "raw_message":
                message,
        }

        self.save_event(event)

        print("Local firewall event recorded.")

    def web_message(self, message:str):
        web_match=re.search(
            r"(?P<ip>\d{1,3}"
            r"(?:\.\d{1,3}){3})"
            r"\s+\S+\s+\S+\s+"
            r"\[[^\]]+\]\s+"
            r'"(?P<method>[A-Z]+)\s+'
            r"(?P<path>\S+)"
            r'(?:\s+HTTP/[0-9.]+)?"\s+'
            r"(?P<status>\d{3})",
            message,
        )

        if web_match is None:
            web_match=re.search(
                r"(?P<ip>\d{1,3}"
                r"(?:\.\d{1,3}){3})"
                r"\s+-?\s*"
                r"(?P<method>"
                r"GET|POST|PUT|DELETE|PATCH|HEAD)"
                r"\s+"
                r"(?P<status>\d{3})",
                message,
                re.IGNORECASE,
            )

        if web_match is None:
            return
        status_code=int(web_match.group("status"))

        if status_code in [401, 403]:
            status="failed"
        else:
            status="success"

        event={
            "timestamp": pd.Timestamp.now(),

            "username": "unknown",

            "ip_address": web_match.group("ip"),

            "status": status,

            "event_type": "web_request",

            "http_method": web_match.group("method").upper(),

            "path":web_match.group("path"),

            "status_code": status_code,

            "source_ip": "127.0.0.1",

            "raw_message": message,

        }

        self.save_event(event)

        print("Local web event recorded.")

    def vpn_message(self, message:str):
        lower_message=(message.lower())

        vpn_markers=[
            "vpn",
            "openvpn",
            "wireguard",
            "wg-quick",
            "ipsec",
            "strongswan",
            "nesessionmanager",
            "networkextension",
            "rasclient",
            "tunnel",
        ]

        if not any(marker in lower_message for marker in vpn_markers):
            return

        failure_words=[
            "authentication failed",
            "auth failed",
            "login failed",
            "connection failed",
            "failed",
            "denied",
            "rejected",
        ]

        success_words=[
            "authentication successful",
            "authenticated",
            "connected",
            "connection established",
            "tunnel established",
        ]

        disconnect_words=[
            "disconnected",
            "disconnect",
            "tunnel down",
        ]

        if any(word in lower_message for word in failure_words):
            status="failed"

        elif any(word in lower_message for word in disconnect_words):
            status="disconnected"

        elif any(word in lower_message for word in success_words):
            status="success"

        else:
            return

        ip_match=re.search(
            r"(?P<ip>\d{1,3}"
            r"(?:\.\d{1,3}){3})",
            message,
        )

        if ip_match is not None:
            ip_address=ip_address.group("ip")

        else:
            ip_address="unknown"

        username_match=re.search(
            r"(?:for|user|username[=:]?)\s+"
            r"(?P<username>[A-Za-z0-9._-]+)",
            message,
            re.IGNORECASE,
        )

        if username_match is not None:
            username=(username_match.group("username"))

        else:
            username="unknown"

        if(status in[
            "success",
            "failed",
        ]
        and ip_address != "unknown"
        ):

            event_type ="vpn_login"

        else:
            event_type="vpn_event"

        event={
            "timestamp": pd.Timestamp.now(),

            "username": username,

            "ip_address": ip_address,

            "status": status,

            "event_type": event_type,

            "source_ip": "127.0.0.1",

            "raw_message": message,
        }

        self.save_event(event)

        print("Local VPN event recorded.")

    def monitor_web(self,paths:list[str]):
        log_path=None

        for path in paths:

            matches=glob.glob(path)

            if matches:

                log_path=max(
                    matches, 
                    key=lambda file:
                    __import__("os").path.getmtime(
                        file
                    ),

                )

                break

        if log_path is None:
            print("No supported local web access log was found.")

            return

        print(f"Monitoring web log: {log_path}")

        try:

            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as log_file:

                log_file.seek(0,2)

                while self.running:
                    line=(log_file.readline())

                    if not line:
                        time.sleep(0.5)

                        continue

                    self.web_message(line.strip())

        except(OSError, PermissionError) as error:
            print(f"Web log monitoring error: {error}")



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

        self.stream_command(command, self.log_message, "MacOS SSH monitoring")   

    def macos_firewall(self):
        print("Monitoring local MacOS firewall activity...") 

        command=[
            "/usr/bin/log",
            "stream",
            "--style",
            "syslog",
            "--predicate",

            (
                'process=="socketfilterfw" '
                'OR subsystem CONTAINS[c] "alf"'
            ),
        ]

        self.stream_command(command, self.parse_firewall, "MacOS firewall monitoring")

    def macos_web(self):
        print("Checking for local MacOS web server logs...")

        web_logs=[
            "/var/log/apache2/access_log",
            "/opt/homebrew/var/log/nginx/access.log",
            "/usr/local/var/log/nginx/access.log",
        ]

        self.monitor_web(web_logs)

    def macos_vpn(self):
        print("Monitoring local MacOS VPN activity...")

        command=[
            "/usr/bin/log",
            "stream",
            "--style",
            "syslog",
            "--predicate",
            (
                'process=="nesessionmanager" '
                'OR process=="neagent" '
                'OR subsystem CONTAINS[c] '
                '"NetworkExtension"'
            ),
        ]

        self.stream_command(command, self.vpn_message, "MacOS VPN monitoring")

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
            self.stream_command(command, self.log_message, "Linux SSH monitoring")

        except FileNotFoundError:
            self.monitor_linux_auth_file()


    #backup case for linux
    def monitor_linux_auth_file(self):
        print("Trying /var/log/auth.log...")

        command=[
            "tail",
            "-F",
            "/var/log/auth.log",
        ]

        self.stream_command(command, self.log_message, "Linux auth.log monitoring")

    def linux_firewall(self):
        print("Monitoring local Linux firewall activity...")

        command=[
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "cat",
            "-k",
        ]

        self.stream_command(command, self.parse_firewall, "Linux firewall monitoring")

    def linux_web(self):
        print("Checking for local Linux web server logs...")

        web_logs=[
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
            "/var/log/httpd/access_log",
        ]

        self.monitor_web(web_logs)

    def linux_vpn(self):
        print("Monitoring local Linux VPN activity...")

        command=[
            "journalctl",
            "-f",
            "-n",
            "0",
            "-o",
            "cat",
        ]

        self.stream_command(command,self.vpn_message, "Linux VPN monitoring")

    def monitor_windows(self):
        print("Monitoring Windows Security events...")

        while self.running:
            try:
                events=self.windows_events()

                for event in events:

                    record_id=event.get("RecordId")

                    if record_id is None:
                        continue

                    event_key=("security", record_id)

                    if(event_key in self.seen_by_windows):
                        continue

                    self.seen_by_windows.add(event_key)

                    event_id=(
                        event.get(
                            "Id"
                        )
                    )

                    if event_id in [

                        4624, 4625, 5157
                    ]:
                        

                        username=(
                            event.get(
                                "TargetUserName"
                            )
                        )

                        ip_address=(
                            event.get(
                                "IpAddress"
                            )
                        )

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
                        else:
                            status="failed"

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

                    elif event_id==5157:
                        source_address=(
                            event.get("SourceAddress"))

                        destination_address=(event.get("DestAddress"))

                        ip_address=(
                            source_address or destination_address or "unknown"
                        )

                        normalized_event={
                            "timestamp": pd.Timestamp.now(),

                            "username": "unknown",

                            "ip_address": ip_address,

                            "status": "blocked",

                            "event_type": "firewall_block",

                            "source_address": source_address,

                            "source_port": event.get("SourcePort"),

                            "destination_port": event.get("DestPort"),

                            "application": event.get("Application"),

                            "source_ip": "127.0.0.1",
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
    $xml=[xml]$event.ToXml()
    $values=@{}
    
    foreach ($item in $xml.Event.EventData.Data){
        $values[$item.Name]=$item.'#text'
    }
    [PSCustomObject]@{
        RecordId        =$event.RecordId
        Id              =$event.Id
        TargetUserName  =$values['TargetUserName']
        IpAddress       =$values['IpAddress']
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
            check=True,
        )

        events=[]

        for line in result.stdout.splitlines():
            line=line.strip()

            if not line:
                continue

            events.append(json.loads(line))

        return events


    def windows_vpn(self):
        print("Monitoring Windows VPN activity...")

        while self.running:

            try:
                events=(self.windows_vpn_events())

                for event in events:
                    record_id=(event.get("RecordId"))

                    if record_id is None:
                        continue

                    if (record_id in self.seen_windows_vpn):
                        continue

                    self.seen_windows_vpn.add(record_id)

                    message=(event.get("Message"))

                    if message: 
                        self.vpn_message(message)

            except(OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:

                print(f"Windows VPN monitoring error: {error}")

            time.sleep(2)

    def windows_vpn_events(self)-> list[dict]:

        powershell_script=r"""

$events = Get-WinEvent `
    -LogName 'Microsoft-Windows-RasClient/Operational' `
    -MaxEvents 25 `
    -ErrorAction SilentlyContinue

foreach ($event in $events){
    [PSCustomObject]@{
        RecordId = $event.RecordId
        Id       = $event.Id
        Message  = $event.FormatDescription()
    }| ConvertTo-Json -Compress
    
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

    def windows_web(self):

        print("Checking for local IIS web logs...")

        paths=glob.glob(
            r"C:\inetpub\logs\LogFiles"
            r"\W3SVC*\u_ex*.log"
        )

        if not paths:
            print("No local IIS access log found.")

            return

        log_path=max(
            paths,
            key=os.path.getmtime,
        )

        print(f"Monitoring IIS log: {log_path}")

        fields=None

        try:
            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as log_file:

                for _ in range(100):
                    line=log_file.readline()

                    if not line:
                        break

                    if line.startswith("#Fields:"):
                        fields=(line.replace("#Fields:").strip().split())

                #watch new traffic only

                log_file.seek(0,2)

                while self.running:

                    line=(log_file.readline())

                    if not line:
                        time.sleep(0.5)
                        continue

                    line=line.strip()

                    if line.startswith("#Fields:"):
                        fields=(line.replace("#Fields:", "").strip().split())

                        continue

                    if(line.startswith('#') or not fields):
                        continue

                    values=line.split()

                    if len(values) != len(fields):
                        continue

                    row=dict(
                        zip(
                            fields,
                            values,
                        )
                    )

                    client_ip=(row.get("c-ip"))

                    method=(row.get("cs-method"))

                    path=(row.get("cs-uri-stem"))

                    status_code=(row.get("sc-status"))

                    if(
                        not client_ip
                        or not method
                        or not path
                        or not status_code
                    ):
                        continue

                    try:
                        status_code=int(status_code)
                    except ValueError:
                        continue

                    status=(
                        "failed"
                        if status_code in[
                            401, 403,
                        ]
                        else "success"
                    )

                    event={
                        "timestamp": pd.Timestamp.now(),

                        "username": "unknown",

                        "ip_address": client_ip,

                        "status": status,

                        "event_type": "web_request",

                        "http_method": method,

                        "path": path,

                        "status_code": status_code,

                        "source_ip": "127.0.0.1",
                    }

                    self.save_event(event)

        except OSError as error:
            print(f"IIS monitoring error: {error}")



    def return_logs(self)->pd.DataFrame:
        with self.lock:
            event_copy=(self.events.copy())
        return pd.DataFrame(event_copy)

    def stop_run(self):
        self.running=False

        for process in self.processes:
            try:
                if process.poll() is None:

                    process.terminate()

            except OSError:
                pass

        self.processes.clear()


