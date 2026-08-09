import re
import socket 
from datetime import datetime
import pandas as pd

HOST="0.0.0.0"
PORT=5514 

#convert messages format
def auth_log(message:str,ip_add:str)->dict | None:
    fail_login=re.search(
        r"Failed password for(?:invalid user)? "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:.\d{1,3}){3})", message,
        re.IGNORECASE,    
    )

    if fail_login: return {
        "timestamp":datetime.now(),
        "username":fail_login.group("username"),
        "ip_address":fail_login.group("ip"),
        "status": "failed",

    }

    success_login=re.search(
        r"Accepted(?:password|publickey) for "
        r"(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1.3}){3})", message,
        re.IGNORECASE,
    )
    
    if success_login: return{
        "timestamp":datetime.now(),
        "username":success_login.group("username"),
        "ip_address":success_login.group("ip"),
        "status":"success",
    }
    return None

#network listener and collects events
def collect_net_logs()->pd.DataFrame:
    logins=[]
    net_sock=socket.socket(
        socket.AF_INET, #IPv4 addresses
        socket.SOCK_DGRAM, #use UDP
    )
    net_sock.bind((HOST,PORT))
    print(f"Listening for authentication logs on UDP port {PORT}...")
    print("Press Control+C to stop.\n")

    try:
        while True:
            data, address=net_sock.recvfrom(65535)#max amount of data

            ip_add=address[0]
            message=data.decode("utf-8",errors="replace",
    )
            print(f"Log received from {ip_add}:")
            print(message)

            parse_check=auth_log(message, ip_add,

        )

            if parse_check is not None:
                logins.append(parse_check)
                print("Authentication event recorded.\n")

            else:
                print("Log received but not a supported authentication event.\n")

    except KeyboardInterrupt:
        print("\nStopping live log collection...")

    finally:
        net_sock.close()

    return pd.DataFrame(logins)



   
