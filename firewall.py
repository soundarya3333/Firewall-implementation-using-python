import subprocess
import socket
from scapy.all import sniff, IP, TCP
import streamlit as st
import pandas as pd
import plotly.express as px

# Network interface and initial blocked and allowed settings
interface = "Wi-Fi"
blocked_ips = ["192.168.1.100", "192.168.1.200"]
blocked_ports = [80, 443]  # Initial blocked ports
allowed_ports = [22, 8080, 3306]  # Example allowed ports
packet_count = 10
packet_records = []

# Functions to manage Windows Firewall rules
def block_port_in_windows(port):
    rule_name = f"Block_Port_{port}"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" protocol=TCP dir=in action=block localport={port}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Blocked Port: {port}")
    except subprocess.CalledProcessError as e:
        st.error(f"Failed to block port {port}: {e}")

def unblock_port_in_windows(port):
    rule_name = f"Block_Port_{port}"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}" protocol=TCP localport={port}'
    try:
        subprocess.run(command, shell=True, check=True)
        st.success(f"Unblocked Port: {port}")
    except subprocess.CalledProcessError as e:
        st.error(f"Failed to unblock port {port}: {e}")

# Function to create packet records
def create_packet_record(packet, status):
    return {
        "Source IP": packet[IP].src if IP in packet else "N/A",
        "Destination IP": packet[IP].dst if IP in packet else "N/A",
        "Source Port": packet[TCP].sport if packet.haslayer(TCP) else "N/A",
        "Destination Port": packet[TCP].dport if packet.haslayer(TCP) else "N/A",
        "Protocol": "TCP" if packet.haslayer(TCP) else "Other",
        "Status": status
    }

# Function to process packets and determine their status
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if src_ip in blocked_ips or dst_ip in blocked_ips:
            packet_records.append(create_packet_record(packet, "Blocked"))
            return

    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        if src_port in blocked_ports or dst_port in blocked_ports:
            packet_records.append(create_packet_record(packet, "Blocked"))
            return

    packet_records.append(create_packet_record(packet, "Allowed"))

# Sniff packets
packets = sniff(count=packet_count, iface=interface)
for packet in packets:
    process_packet(packet)

# Convert packet records to a DataFrame
packet_df = pd.DataFrame(packet_records)

# Retrieve firewall's IP address
def get_firewall_ip():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return ip_address

firewall_ip = get_firewall_ip()

# Streamlit app layout
st.title("Firewall Packet Monitoring")

# Dropdown to block a port (shows only allowed ports)
selected_port_to_block = st.selectbox("Block Port", allowed_ports)
if st.button("Block Port"):
    if selected_port_to_block:
        allowed_ports.remove(selected_port_to_block)
        blocked_ports.append(selected_port_to_block)
        block_port_in_windows(selected_port_to_block)

# Dropdown to allow a port (shows only blocked ports)
selected_port_to_allow = st.selectbox("Allow Port", blocked_ports)
if st.button("Allow Port"):
    if selected_port_to_allow:
        blocked_ports.remove(selected_port_to_allow)
        allowed_ports.append(selected_port_to_allow)
        unblock_port_in_windows(selected_port_to_allow)

# Display table with packet details
st.subheader("Packet Table")
st.dataframe(packet_df)

# Display the firewall's IP address below the table
st.subheader("Firewall IP Address")
st.write(f"Firewall IP Address: {firewall_ip}")

# Create a stacked bar chart for blocked and allowed packets
if not packet_df.empty:
    # Count the packets by source and status
    packet_counts = packet_df.groupby(['Source IP', 'Status']).size().reset_index(name='Count')

    # Create the stacked bar chart
    fig = px.bar(packet_counts, x='Source IP', y='Count', color='Status',
                 title='Packet Status by Source IP',
                 labels={'Count': 'Number of Packets', 'Source IP': 'Source IP'},
                 text='Count')

    # Update layout for better readability
    fig.update_traces(texttemplate='%{text}', textposition='outside')
    fig.update_layout(barmode='stack', xaxis_title='Source IP', yaxis_title='Number of Packets')

    # Display the chart in Streamlit
    st.plotly_chart(fig)
