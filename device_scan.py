import ipaddress
import platform
import socket
import subprocess 
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
def get_ip()->tuple[str,str]:
    
    ignore_these=(
        "bridge",
        "utun",
        "docker",
        "veth",
        "vmnet",
        "lo",
        "tailscale",
    )

    for interface, addresses in psutil.net_if_addrs().items():

        if interface.lower().startswith(ignore_these):
            continue

        stats=psutil.net_if_stats().get(interface)

        if stats is None or not stats.isup:
            continue

        for address in addresses:
            if (address.family == socket.AF_INET 
                and not address.address.startswith("127.") 
                and address.netmask
            ):
                
                print("Using physical interface:", interface)
                print("Local IP:", address.address)

                return interface, address.address
            
    raise RuntimeError("Could not find an active physical network interface.")
                
            

#find subnet

def get_subnet():
    interface, local_ip=get_ip()

    addresses=psutil.net_if_addrs()[interface]

    for address in addresses:
                if(
                    address.family==socket.AF_INET
                    and address.address==local_ip
                    and address.netmask
                ):
                    network=ipaddress.ip_network(f"{local_ip}/{address.netmask}", strict=False)

                print("Detected interface:", interface)
                print("Detected local IP:", local_ip)
                print("Detected network:", network)

                
                return local_ip, network
    raise RuntimeError("Could not determine the network.")


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

def check_TCP(ip_address:str, port:int)->bool:
    sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.2)

    try:
        result=sock.connect_ex((ip_address,port))

        return result==0
    
    finally:
        sock.close()

def scan_services(ip_address:str)->dict | None:
    open_ports=[]
    for port, service in COMMON_PORTS.items():
        if check_TCP(ip_address, port):
            open_ports.append(
                {
                "port":port,
                "service":service,
                }
            )


    port_nums=[
        item["port"] for item in open_ports
    ]

    services=[
        item["service"] for item in open_ports
    ]

    findings=[]

    for port in port_nums:
        if port in REVIEW_PORTS:
            findings.append(REVIEW_PORTS[port])

    if findings:
        attention="Review"
    else:
        attention="Normal"
    return{
        "ip_address": ip_address,
        "open_ports": ", ".join(str(port) for port in port_nums),
        "services":", ".join(services),
        "attention": attention,
        "findings": ", ".join(findings),
    }

def perform_device_scan():
    interface, local_ip= get_ip()

    print("Scanning your device...")
    print("Interface:", interface)
    print("Device IP:", local_ip)

    result=scan_services(local_ip)

    if result is None:
        devices=[]
    else:
        devices=[result]

    device_cols=[
        "ip_address",
        "open_ports",
        "services",
        "attention",
        "findings",
    ]

    device_df=pd.DataFrame(devices,columns=device_cols)

    return(device_df, local_ip, interface)

    



