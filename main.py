import psutil
import requests
import ipaddress
import matplotlib.pyplot as plt
import cartopy.crs as ccrs
import cartopy.feature as cfeature
import datetime
import os

LOG_FILE = "connection_log_psutil.txt"

def is_public_ip(ip):
    """
    Determine if an IP address is public (not local or loopback).

    Args:
        ip (str): The IP address to check.

    Returns:
        bool: True if IP is public, False otherwise.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback)
    except:
        return False

def get_ip_geo(ip, cache):
    """
    Lookup geolocation and organization info for an IP address using ipinfo.io.

    Args:
        ip (str): The IP address to lookup.
        cache (dict): Dictionary to cache results and avoid duplicate requests.

    Returns:
        tuple: (latitude, longitude, 'city, country', organization)
    """
    if ip in cache:
        return cache[ip]
    try:
        res = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if res.status_code == 200:
            info = res.json()
            if "loc" in info:
                lat, lon = map(float, info["loc"].split(","))
                city = info.get("city", "")
                country = info.get("country", "")
                org = info.get("org", "")
                geo_str = f"{city}, {country}"
                cache[ip] = (lat, lon, geo_str, org)
                return lat, lon, geo_str, org
    except:
        pass
    # If failed, return defaults for this IP
    cache[ip] = (None, None, "Unknown", "Unknown")
    return None, None, "Unknown", "Unknown"

def collect_connections():
    """
    Collects all current public network connections on the system.

    Returns:
        list: List of tuples (local_ip, remote_ip, process_name, process_id)
    """
    connections = []
    # psutil.net_connections(kind='inet') retrieves all inet (TCP/UDP) connections
    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            remote_ip = conn.raddr.ip
            if not is_public_ip(remote_ip):
                continue  # Skip local/private/loopback IPs
            local_ip = conn.laddr.ip
            pid = conn.pid
            try:
                pname = psutil.Process(pid).name()
            except:
                pname = "unknown"
            connections.append((local_ip, remote_ip, pname, pid))
    return connections

def print_connections(connections, ip_cache):
    """
    Prints a formatted table of all current public network connections.

    Args:
        connections (list): List of connection tuples.
        ip_cache (dict): Dictionary of geolocation/org info for remote IPs.
    """
    print("\nActive Public Network Connections:\n")
    print("{:<18} {:<18} {:<20} {:<8} {:<25} {:<25} {:<25}".format(
        "Local IP", "Remote IP", "Process", "PID", "Location", "Org", "Timestamp"
    ))
    print("-" * 140)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for local_ip, remote_ip, pname, pid in connections:
        lat, lon, geo_str, org = get_ip_geo(remote_ip, ip_cache)
        print("{:<18} {:<18} {:<20} {:<8} {:<25} {:<25} {:<25}".format(
            local_ip, remote_ip, pname, pid, geo_str, org, now
        ))

def log_connections(connections, ip_cache, filename=LOG_FILE):
    """
    Logs all current public network connections to a file with timestamps.

    Args:
        connections (list): List of connection tuples.
        ip_cache (dict): Dictionary of geolocation/org info for remote IPs.
        filename (str): Path to the log file.
    """
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mode = 'a' if os.path.exists(filename) else 'w'
    with open(filename, mode, encoding="utf-8") as f:
        for local_ip, remote_ip, pname, pid in connections:
            lat, lon, geo_str, org = get_ip_geo(remote_ip, ip_cache)
            f.write(f"{now} | {local_ip} -> {remote_ip} | Process: {pname} (PID: {pid}) | Location: {geo_str} | Org: {org}\n")

def plot_on_map(connections, ip_cache, my_lat=1.29, my_lon=103.85, filename="connections_map.png"):
    """
    Plots all current public network connections on a world map.

    Args:
        connections (list): List of connection tuples.
        ip_cache (dict): Dictionary of geolocation/org info for remote IPs.
        my_lat (float): Latitude of the user's location (default: Singapore).
        my_lon (float): Longitude of the user's location (default: Singapore).
        filename (str): Path to save the generated map image.
    """
    fig = plt.figure(figsize=(16, 8))
    ax = plt.axes(projection=ccrs.PlateCarree())
    ax.stock_img()
    ax.add_feature(cfeature.BORDERS)
    ax.add_feature(cfeature.COASTLINE)
    ax.add_feature(cfeature.LAND, facecolor='lightgray')
    ax.add_feature(cfeature.OCEAN, facecolor='lightblue')

    # Plot user's location
    ax.plot(my_lon, my_lat, marker='o', color='red', markersize=10, label='Your Device', transform=ccrs.PlateCarree())

    # Plot each connection as a blue dot and line
    for local_ip, remote_ip, pname, pid in connections:
        lat, lon, geo_str, org = get_ip_geo(remote_ip, ip_cache)
        if lat is None or lon is None:
            continue
        ax.plot(lon, lat, marker='o', color='blue', markersize=7, transform=ccrs.PlateCarree())
        ax.plot([my_lon, lon], [my_lat, lat], color='green', linewidth=1, transform=ccrs.PlateCarree())
        ax.text(lon, lat, f"{geo_str}", fontsize=7, transform=ccrs.PlateCarree())

    plt.title("Public Network Connections (Geolocated)", fontsize=16)
    plt.legend()
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    plt.show()
    print(f"Saved map as {filename}")

if __name__ == "__main__":
    """
    Main script logic:
      - Collects all current public network connections
      - Prints connections as a table
      - Logs to a file with timestamp
      - Visualizes connections on a world map
    """
    print("Scanning and visualizing connections (excluding private/local IPs)...\n")
    ip_cache = {}
    connections = collect_connections()
    print_connections(connections, ip_cache)
    log_connections(connections, ip_cache)
    plot_on_map(connections, ip_cache)
    print(f"\nConnections logged to {LOG_FILE}")
