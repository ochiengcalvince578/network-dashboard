import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP, conf
from collections import defaultdict
import time 
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket

# Configure logging 
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }

        self.packet_data = []
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.capture_error = None

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')
    
    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant info"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': str(packet[TCP].flags)
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })
                    
                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Keep only last 10000 packets to prevent memory issues
                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)
                    
        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            if not self.packet_data:
                return pd.DataFrame()
            return pd.DataFrame(self.packet_data)

def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    
    if len(df) == 0:
        st.warning("⚠️ No packets captured yet. Waiting for network traffic...")
        st.info("""
        **Troubleshooting Tips:**
        - Make sure you're running Streamlit with administrator/root privileges
        - Try: `sudo streamlit run your_script.py` (Linux/Mac) or run as Administrator (Windows)
        - Generate some network traffic (browse websites, ping servers, etc.)
        - Check if your firewall is blocking packet capture
        """)
        return

    # Protocol distribution
    protocol_counts = df['protocol'].value_counts()
    fig_protocol = px.pie(
        values=protocol_counts.values,
        names=protocol_counts.index,
        title="Protocol Distribution",
        hole=0.3
    )
    fig_protocol.update_traces(textposition='inside', textinfo='percent+label')
    st.plotly_chart(fig_protocol, use_container_width=True)

    # Packets timeline
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size().reset_index()
    df_grouped.columns = ['timestamp', 'count']
    
    fig_timeline = px.line(
        df_grouped,
        x='timestamp', 
        y='count',
        title="Packets per Second"
    )
    fig_timeline.update_layout(xaxis_title="Time", yaxis_title="Packet Count")
    st.plotly_chart(fig_timeline, use_container_width=True)

    # Top source IPs
    top_sources = df['source'].value_counts().head(10)
    fig_sources = px.bar(
        x=top_sources.index,
        y=top_sources.values,
        title="Top 10 Source IP Addresses",
        labels={'x': 'IP Address', 'y': 'Packet Count'}
    )
    fig_sources.update_layout(xaxis_tickangle=-45)
    st.plotly_chart(fig_sources, use_container_width=True)

    # Protocol statistics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Unique Sources", df['source'].nunique())
    with col2:
        st.metric("Unique Destinations", df['destination'].nunique())
    with col3:
        st.metric("Avg Packet Size", f"{df['size'].mean():.0f} bytes")

def start_packet_capture(interface=None, packet_count=0):
    """Start packet capture in a separate thread"""
    
    processor = PacketProcessor()

    def capture_packets():
        try:
            logger.info(f"Starting packet capture on interface: {interface or 'default'}")
            # Use filter to capture only IP packets and limit to reduce noise
            sniff(
                iface=interface,
                prn=processor.process_packet,
                store=False,
                count=packet_count,
                filter="ip"  # Only capture IP packets
            )
        except PermissionError:
            processor.capture_error = "Permission denied. Please run with administrator/root privileges."
            logger.error(processor.capture_error)
        except Exception as e:
            processor.capture_error = f"Capture error: {str(e)}"
            logger.error(processor.capture_error)

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    return processor

def main():
    """Main function to run the dashboard"""
    st.set_page_config(
        page_title="Network Traffic Analysis",
        page_icon="📡",
        layout="wide"
    )
    
    st.title("📡 Real-time Network Traffic Analysis")
    
    # Sidebar for configuration
    with st.sidebar:
        st.header("Configuration")
        
        # Get available interfaces
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            selected_interface = st.selectbox(
                "Network Interface",
                options=[None] + interfaces,
                format_func=lambda x: "Auto-detect" if x is None else x
            )
        except:
            selected_interface = None
            st.info("Could not list network interfaces")
        
        auto_refresh = st.checkbox("Auto-refresh (every 5s)", value=True)
        
        if st.button("🔄 Restart Capture"):
            if 'processor' in st.session_state:
                del st.session_state.processor
            st.rerun()

    # Initialize packet processor in session state
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture(interface=selected_interface)
        st.session_state.start_time = time.time()
        st.session_state.last_refresh = time.time()

    # Check for capture errors
    if st.session_state.processor.capture_error:
        st.error(f"❌ {st.session_state.processor.capture_error}")
        st.stop()

    # Create dashboard layout
    col1, col2, col3 = st.columns(3)

    # Get current data 
    df = st.session_state.processor.get_dataframe()

    # Display metrics 
    with col1:
        st.metric("Total Packets", len(df))
    
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.0f}s")
    
    with col3:
        if len(df) > 0:
            packets_per_sec = len(df) / max(duration, 1)
            st.metric("Avg Packets/sec", f"{packets_per_sec:.1f}")
        else:
            st.metric("Avg Packets/sec", "0")

    # Display visualizations
    st.subheader("📊 Traffic Analysis")
    create_visualizations(df)

    # Display recent packets
    st.subheader("📋 Recent Packets")
    if len(df) > 0:
        display_columns = ['timestamp', 'source', 'destination', 'protocol', 'size']
        # Add port columns if they exist
        if 'src_port' in df.columns:
            display_columns.append('src_port')
        if 'dst_port' in df.columns:
            display_columns.append('dst_port')
        
        recent_df = df.tail(20)[display_columns].copy()
        recent_df['timestamp'] = recent_df['timestamp'].dt.strftime('%H:%M:%S.%f').str[:-3]
        st.dataframe(recent_df, use_container_width=True, height=400)
    else:
        st.info("No packets captured yet...")

    # Auto refresh logic
    if auto_refresh:
        current_time = time.time()
        if current_time - st.session_state.last_refresh >= 5:
            st.session_state.last_refresh = current_time
            st.rerun()
        else:
            time_until_refresh = 5 - (current_time - st.session_state.last_refresh)
            st.caption(f"Next refresh in {time_until_refresh:.1f}s...")
            time.sleep(1)
            st.rerun()

if __name__ == "__main__":
    main()