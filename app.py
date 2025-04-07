import streamlit as st
from packet_utils import start_capture, calculate_entropy
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(layout="wide")
st.title("🛡️ Live Network Anomaly Detector")

if st.button("Start Capture"):
    with st.spinner("Sniffing network traffic..."):
        df = start_capture(timeout=15)  # 15-second capture
        
        # Metrics
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Packets", len(df))
        col2.metric("Anomalies", df['is_anomaly'].sum())
        col3.metric("Entropy", round(calculate_entropy(df['size']), 2))
        
        # Visualizations
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        df.set_index("time")["size"].plot(ax=ax1, title="Packet Sizes")
        df['source'].value_counts().head(5).plot(kind='bar', ax=ax2, title="Top Sources")
        st.pyplot(fig)
        
        # Raw data
        st.dataframe(df.sort_values("time", ascending=False))
        
        # Download button
        st.download_button(
            "Download Data",
            df.to_csv(index=False),
            "network_traffic.csv"
        )