import ipaddress
import platform
import socket
import subprocess 
from concurrent.futures import ThreadPoolExecutor, as_completed
import pandas as pd
import psutil

#check services
COMMON_PORTS={
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}

REVIEW_PORTS={
    21: "FTP exposed",
    23: "Telnet exposed",
    445: "SMB exposed",
    3389:"RDP exposed",
    5900: "VNC exposed",
}

#find ip
def get_ip()->str:
    sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(("8.8.8.8",80))
        return sock.getsockname()[0]
    except OSError:
        for address in psutil.net_if_addrs().values():
            for address in addresses:
                if(
                    address.family==socket.AF_INET and not address.address.startswith("127.")
                    and address.netmask
                ):
                    return address.address

        raise RuntimeError("Could not determine this device's IP address.")
    finally:
        sock.close()

#find subnet

def get_network():
    local_ip=get_prim_ip()
    for addresses in psutil.net_if_addrs().values():
        for address in addresses:
            if(
                address.family==socket.AF_INET and address.address==local_ip
                and address.netmask
            ):
                network=ipaddress.ip_network(f"{local_ip}/{address.netmask}",strict=False
                )

                if not network.is_private:
                    raise ValueError("Automatic scanning is limited to private local networks.")
                if network.num_addresses>256:
                    raise ValueError("The detected network contains more than 256 addresses. Automatic scan stopped.")

                return local_ip, network
    raise RuntimeError("Could not determine the local subnet.")

def ping_response(ip_address:str)->bool:
    system=platform.system()

    if system=="Windows":
        command=[
            "ping", "-n", "1", ip_address,
        ]

    elif system in ["Darwin", "Linux"]:
        command =[
            "ping", "-c", "1", ip_address,
        ]
    else: 
        return False

    try:
        result=subprocess.run(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=1.5,
        )
        return result.returncode==0
    except(
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        return False

def check_connections(ip_address:str, port: int)->bool:
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.settimeout(0.2)

    try:
        result=sock.connect_ex(
            (
                ip_address, port,
            )
        )
        return result==0

    finally:
        sock.close()

