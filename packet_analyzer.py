import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, get_if_list
import threading
import time
from datetime import datetime
import logging
from streamlit_autorefresh import st_autorefresh

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class PacketProcessor:
    """Processing and analyzing packets"""

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

    def get_protocol_name(self, protocol_num: int) -> str:
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
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

                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    if len(self.packet_data) > 10000:
                        self.packet_data.pop(0)

        except Exception as e:
            logger.error(f"Error processing packet: {str(e)}")

    def get_dataframe(self) -> pd.DataFrame:
        with self.lock:
            return pd.DataFrame(self.packet_data)


def create_visualizations(df: pd.DataFrame):
    if len(df) > 0:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig_protocol = px.pie(
            values=protocol_counts.values,
            names=protocol_counts.index,
            title="Protocol Distribution")
        st.plotly_chart(fig_protocol, use_container_width=True)

        # Packets over time
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_grouped = df.groupby(df['timestamp'].dt.floor('S')).size()
        fig_timeline = px.line(
            x=df_grouped.index,
            y=df_grouped.values,
            title="Packets per Second")
        st.plotly_chart(fig_timeline, use_container_width=True)

        # Top source IPs
        top_sources = df['source'].value_counts().head(10)
        fig_sources = px.bar(
            x=top_sources.index,
            y=top_sources.values,
            title="Top Source IP Addresses")
        st.plotly_chart(fig_sources, use_container_width=True)


def start_packet_capture():
    """Start packet capture in a separate thread"""
    processor = PacketProcessor()

    # Print interface list once (for debugging)
    interfaces = get_if_list()
    st.sidebar.write("Available Interfaces:")
    st.sidebar.write(interfaces)

    # Set your correct interface here (use get_if_list() to choose)
    interface_name = 'Wi-Fi'  # <- Change if needed

    def capture_packets(processor: PacketProcessor, iface: str):
        sniff(iface=iface, prn=processor.process_packet, store=False)

    capture_thread = threading.Thread(
        target=capture_packets,
        args=(processor, interface_name),
        daemon=True)
    capture_thread.start()

    return processor


def main():
    st.set_page_config(page_title="Network Traffic Analysis", layout='wide')
    st.title("📡 Real-time Network Traffic Analysis")

    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture()
        st.session_state.start_time = time.time()

    processor = st.session_state.processor
    df = processor.get_dataframe()

    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f} s")

    create_visualizations(df)

    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(df.tail(10)[
            ['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True)

    st_autorefresh(interval=2000, limit=None, key="refresh")



if __name__ == '__main__':
    main()
