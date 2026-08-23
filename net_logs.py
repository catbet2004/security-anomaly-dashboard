import re
import socket
import threading
from datetime import datetime

import pandas as pd

HOST="0.0.0.0"
PORT=5514 

#convert messages format
def auth_log(message:str,ip_add:str)->dict | None:
    fail_login=re.search(
        r"Failed password for(?: invalid user)? "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:.\d{1,3}){3})", 
        message,
        re.IGNORECASE,    
    )

    if fail_login: 
        return {
            "timestamp":datetime.now(),
            "username":fail_login.group("username"),
            "ip_address":fail_login.group("ip"),
            "status": "failed",
            "event_type":"ssh_login",
            "source_ip": ip_add,

        }

    success_login=re.search(
        r"Accepted (?:password|publickey) for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})", 
        message,
        re.IGNORECASE,
    )
    
    if success_login: 
        return{
            "timestamp":datetime.now(),
            "username":success_login.group("username"),
            "ip_address":success_login.group("ip"),
            "status":"success",
            "event_type":"ssh_login",
            "source_ip": ip_add,
        }
    return None

def firewall_logs(message:str, source_ip: str)->dict | None:
    block=re.search(
        r"(?:BLOCK|DROP).*?"
        r"SRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?"
        r"DPT=(?P<port>\d+)",
        message,
        re.IGNORECASE
    )

    if block:
        return{
            "timestamp":datetime.now(),
            "username":"unknown",
            "ip_address": block.group("ip"),
            "status":"blocked",
            "event_type":"firewall_block",
            "destination_port":int(block.group("port")),"source_ip":source_ip,
        }
    return None

def vpn_logs(message:str, source_ip: str)->dict | None:
    fail_vpn=re.search(
        r"VPN authentication failed for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        message,
        re.IGNORECASE,
    )

    if fail_vpn:
        return{
            "timestamp":datetime.now(),
            "username": fail_vpn.group("username"),
            "ip_address": fail_vpn.group("ip"),
            "status":"failed",
            "event_type":"vpn_login",
            "source_ip": source_ip,
        }
    success_vpn=re.search(
        r"VPN authentication successful for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        message,
        re.IGNORECASE,
    )
    if success_vpn:
        return {
            "timestamp":datetime.now(),
            "username": success_vpn.group("username"),
            "ip_address": success_vpn.group("ip"),
            "status":"success",
            "event_type":"vpn_login",
            "source_ip": source_ip,
        }
    
    return None

def web_serve(message: str, source_ip:str)->dict | None:
    web_req=re.search(
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
        r".*?"
        r"(?P<method>GET|POST|PUT|DELETE|PATCH)"
        r"\s+(?P<path>\S+)"
        r".*?"
        r"(?P<status_code>\d{3})",
        message,
        re.IGNORECASE,

    )
    if web_req:
        stat_code=int(
            web_req.group("status_code")
        )
        if stat_code in [401,403]:
            status="failed"
        else:
            status="success"
        return {
            "timestamp":datetime.now(),
            "username": "unknown",
            "ip_address": web_req.group("ip"),
            "status": status,
            "event_type":"web_request",
            "source_code": stat_code,
            "source_ip": source_ip,


        }
    
    return None

def dispatch_logs(message:str, source_ip:str)->dict| None:
    funcs=[
        auth_log,
        firewall_logs,
        vpn_logs,
        web_serve,
    ]
    for functions in funcs:
        result=functions(message,source_ip)

        if result is not None:
            return result

    return None 


#network listener and collects events
class SyslogCollector:
    def __init__(self):
        self.logins=[]
        self.lock=threading.Lock()
        self.running=False
        self.net_sock=socket.socket(
            socket.AF_INET, #IPv4 address
            socket.SOCK_DGRAM, #use UDP 
        )

        self.net_sock.settimeout(1.0)

        self.net_sock.bind((HOST,PORT))

    def start(self):
        if self.running:
            return
        self.running=True
        listener=threading.Thread(
            target=self.listen,
            daemon=True
        )
        listener.start()
    def listen(self):
        print(f"Listening for authentication logs on UDP port {PORT}")

        while self.running:
            try:
                data,address=self.net_sock.recvfrom(65535)
                ip_add=address[0]
                message=data.decode("utf-8", errors="replace")
                print(f"Log received from {ip_add}:")
                print(message)

                message_support=auth_log(message,ip_add)

                if message_support is not None:
                    with self.lock:
                        self.logins.append(message_support)
                        print("Authentication event recorded.\n")
                else:
                    print("Log received but not a supported authentication event.\n")

            except TimeoutError:
                continue

            except OSError:
                break

    def get_logs(self)->pd.DataFrame:
        with self.lock:
            log_copy=self.logins.copy()

        return pd.DataFrame(log_copy)
    
    def stop(self):
        self.running=False
        self.net_sock.close()




        



   
