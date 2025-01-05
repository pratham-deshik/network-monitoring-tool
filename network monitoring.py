import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import signal
import threading
import time
import statistics
import smtplib
from email.mime.text import MIMEText
import pygame
from scapy.all import sniff, IP, TCP, UDP, wrpcap
from PIL import Image, ImageTk, ImageDraw
import matplotlib.pyplot as plt
import io
import csv

# Global variables
start_time = None
stop_event = None
snort_process = None
traffic_metrics = {
    'latency': [],
    'packet_loss': 0,
    'total_packets': 0,
    'total_bytes': 0,
    'packet_sizes': [],
    'timestamps': []
}
last_alert_time = 0
alert_interval = 60  # Minimum time between alerts in seconds
devices = {}  # Track device statuses
last_device_status_check = 0
packet_image = None
packet_draw = None

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = 'kmsuhas2003@gmail.com'
SMTP_PASSWORD = 'wajy nhrd sgcd fhhy'
SENDER_EMAIL = 'kmsuhas2003@gmail.com'
RECIPIENT_EMAIL = 'Gokulnathuc@gmail.com'

def play_alert_sound():
    """Play an alert sound."""
    try:
        pygame.mixer.init()
        pygame.mixer.music.load('assets/alert.wav')
        pygame.mixer.music.play()
    except Exception as e:
        messagebox.showerror("Error", f"Error playing sound: {e}")

def start_capture():
    """Start capturing network packets."""
    global start_time, stop_event
    stop_event = threading.Event()
    start_time = time.time()
    update_status("Capturing...")
    launch_snort()
    sniff_thread = threading.Thread(target=packet_sniffing)
    sniff_thread.start()
    schedule_performance_update()

def packet_sniffing():
    """Sniff network packets and process them."""
    sniff(prn=process_packet, stop_filter=lambda x: stop_event.is_set(), filter="ip")

def process_packet(packet):
    """Process each captured packet and update the GUI with packet details."""
    global start_time
    if IP in packet:
        timestamp = time.time() - start_time if start_time is not None else 0
        packet_info = (f"Source: {packet[IP].src}, Destination: {packet[IP].dst}, "
                       f"Protocol: {packet[IP].proto}, Length: {len(packet)}")
        traffic_metrics['total_packets'] += 1
        traffic_metrics['total_bytes'] += len(packet)
        traffic_metrics['packet_sizes'].append(len(packet))
        traffic_metrics['timestamps'].append(timestamp)
        log_summary_tree.insert("", tk.END, values=(
            traffic_metrics['total_packets'], time.strftime("%Y-%m-%d %H:%M:%S"),
            packet[IP].src, packet[IP].dst, packet[IP].proto, len(packet), packet_info))
        display_in_depth_details(packet)
        visualize_packet(packet)
        update_performance_chart()
        detect_threats(packet)

def detect_threats(packet):
    """Detect unusual threats from packets."""
    global last_alert_time
    if TCP in packet and (packet[TCP].flags == 'S'):
        if time.time() - last_alert_time > alert_interval:
            send_email_alert(f"Possible SYN flood attack detected from {packet[IP].src}")
            play_alert_sound()
            last_alert_time = time.time()
    elif UDP in packet and len(packet) > 1500:
        if time.time() - last_alert_time > alert_interval:
            send_email_alert(f"Possible UDP flood attack detected from {packet[IP].src}")
            play_alert_sound()
            last_alert_time = time.time()

def display_in_depth_details(packet):
    """Display detailed information of the selected packet."""
    in_depth_details_text.config(state=tk.NORMAL)
    in_depth_details_text.delete(1.0, tk.END)

    packet_info = f"Version: {packet.version}\n"
    packet_info += f"Source IP: {packet[IP].src}\n"
    packet_info += f"Destination IP: {packet[IP].dst}\n"
    packet_info += f"Protocol: {packet[IP].proto}\n"
    packet_info += f"Total Length: {len(packet)}\n"
    if packet.haslayer('TCP'):
        packet_info += f"Source Port: {packet['TCP'].sport}\n"
        packet_info += f"Destination Port: {packet['TCP'].dport}\n"
    elif packet.haslayer('UDP'):
        packet_info += f"Source Port: {packet['UDP'].sport}\n"
        packet_info += f"Destination Port: {packet['UDP'].dport}\n"
    
    in_depth_details_text.insert(tk.END, packet_info)
    in_depth_details_text.config(state=tk.DISABLED)

def launch_snort():
    """Launch the Snort IDS process."""
    global snort_process
    command = ['snort', '-A', 'console', '-c', '/etc/snort/snort.conf', '-i', 'eth1:enp0s3', '-Q']
    if snort_process is None or snort_process.poll() is not None:
        snort_process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True
        )
        t = threading.Thread(target=update_output)
        t.start()

def stop_capture():
    """Stop capturing network packets."""
    global start_time, stop_event
    if stop_event:
        stop_event.set()
    end_time = time.time()
    capture_duration = end_time - start_time if start_time else 0
    start_time = None
    stop_snort()
    update_status("Stopped")
    calculate_performance_metrics()

def stop_snort():
    """Stop the Snort IDS process."""
    global snort_process
    if snort_process and snort_process.poll() is None:
        snort_process.send_signal(signal.SIGINT)
        snort_process.wait()
    snort_process = None

def update_output():
    """Update the output of the Snort process in the log text widget."""
    global snort_process
    if snort_process and snort_process.stdout:
        for line in iter(snort_process.stdout.readline, ''):
            pass
        snort_process.stdout.close()

def calculate_performance_metrics():
    """Calculate and display network performance metrics."""
    global start_time, traffic_metrics
    if start_time:
        elapsed_time = time.time() - start_time
        latency_average = statistics.mean(traffic_metrics['latency']) if traffic_metrics['latency'] else 0
        packet_loss_rate = traffic_metrics['packet_loss'] / traffic_metrics['total_packets'] if traffic_metrics['total_packets'] > 0 else 0
        average_bandwidth = traffic_metrics['total_bytes'] / elapsed_time if elapsed_time > 0 else 0
        performance_metrics_text = (f"Elapsed Time: {elapsed_time:.2f} seconds\n"
                                    f"Average Latency: {latency_average:.2f} ms\n"
                                    f"Packet Loss Rate: {packet_loss_rate:.2%}\n"
                                    f"Average Bandwidth: {average_bandwidth:.2f} bytes/sec\n")
        metrics_text.config(state=tk.NORMAL)
        metrics_text.delete(1.0, tk.END)
        metrics_text.insert(tk.END, performance_metrics_text)
        metrics_text.config(state=tk.DISABLED)

def schedule_performance_update():
    """Schedule periodic updates for performance metrics."""
    if start_time is not None:
        calculate_performance_metrics()
        root.after(1000, schedule_performance_update)  # Schedule the next update in 1000 ms (1 second)


def clear_logs():
    """Clear the log text widget."""
    log_summary_tree.delete(*log_summary_tree.get_children())

def send_email_alert(packet_info):
    """Send an email alert when a potential threat is detected."""
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            msg = MIMEText(f"Potential threat detected:\n\n{packet_info}")
            msg['Subject'] = 'Network Security Alert'
            msg['From'] = SENDER_EMAIL
            msg['To'] = RECIPIENT_EMAIL
            server.send_message(msg)
    except smtplib.SMTPException as e:
        messagebox.showerror("Error", f"Failed to send email alert: {e}")

def check_device_status():
    """Check the status of monitored devices and update their status."""
    global last_device_status_check
    current_time = time.time()
    for ip, details in devices.items():
        if current_time - details['last_seen'] > 300:  # Consider offline if not seen for 5 minutes
            details['status'] = 'offline'
    last_device_status_check = current_time

def update_status(status):
    """Update the status label in the GUI."""
    status_label.config(text=f"Status: {status}")

def export_logs():
    """Export logs to a CSV or PCAP file."""
    log_file = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[
            ("CSV files", "*.csv"),
            ("PCAP files", "*.pcap")
        ]
    )

    if log_file.endswith('.csv'):
        export_to_csv(log_file)
    elif log_file.endswith('.pcap'):
        export_to_pcap(log_file)

def export_to_csv(file_path):
    """Export log summary to CSV."""
    with open(file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"])
        for row in log_summary_tree.get_children():
            writer.writerow(log_summary_tree.item(row, 'values'))

def export_to_pcap(file_path):
    """Export packet details to PCAP file."""
    packets = []  # Collect packets for PCAP export
    with open(file_path, 'wb') as file:
        wrpcap(file, packets)

def visualize_packet(packet):
    """Visualize the packet details."""
    global packet_image, packet_draw
    packet_image = Image.new('RGB', (400, 300), 'white')
    packet_draw = ImageDraw.Draw(packet_image)
    packet_draw.text((10, 10), f"Source IP: {packet[IP].src}", fill='black')
    packet_draw.text((10, 30), f"Destination IP: {packet[IP].dst}", fill='black')
    packet_draw.text((10, 50), f"Protocol: {packet[IP].proto}", fill='black')
    packet_draw.text((10, 70), f"Length: {len(packet)}", fill='black')
    image_tk = ImageTk.PhotoImage(packet_image)
    visualization_canvas.create_image(0, 0, anchor=tk.NW, image=image_tk)
    visualization_canvas.image = image_tk

def update_performance_chart():
    """Update performance chart with traffic metrics."""
    fig, ax = plt.subplots()
    ax.plot(traffic_metrics['timestamps'], traffic_metrics['packet_sizes'], label='Packet Sizes')
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Packet Size (bytes)')
    ax.legend()
    plt.tight_layout()
    chart_stream = io.BytesIO()
    plt.savefig(chart_stream, format='png')
    plt.close(fig)
    chart_image = Image.open(io.BytesIO(chart_stream.getvalue()))
    chart_tk = ImageTk.PhotoImage(chart_image)
    performance_chart_canvas.create_image(0, 0, anchor=tk.NW, image=chart_tk)
    performance_chart_canvas.image = chart_tk

def on_closing():
    """Handle the application closing event."""
    stop_capture()
    root.destroy()

def configure_gui():
    """Configure the main GUI elements."""
    global root, log_summary_tree, in_depth_details_text, metrics_text, status_label, visualization_canvas, performance_chart_canvas
    
    root = tk.Tk()
    root.title("Network Monitoring Tool")

    # Top Frame for Status
    top_frame = tk.Frame(root)
    top_frame.pack(fill=tk.X, padx=10, pady=5)
    
    status_label = tk.Label(top_frame, text="Status: Not Capturing", font=("Arial", 12))
    status_label.pack(pady=10)

    # Button Frame
    button_frame = tk.Frame(root)
    button_frame.pack(fill=tk.X, padx=10, pady=5)

    start_button = tk.Button(button_frame, text="Start Capture", command=start_capture,
                            bg="green", fg="white", font=("Arial", 12, "bold"))
    start_button.pack(side=tk.LEFT, padx=5)

    stop_button = tk.Button(button_frame, text="Stop Capture", command=stop_capture,
                        bg="red", fg="white", font=("Arial", 12, "bold"))
    stop_button.pack(side=tk.LEFT, padx=5)

    clear_button = tk.Button(button_frame, text="Clear Log", command=clear_logs,
                            bg="blue", fg="white", font=("Arial", 12, "bold"))
    clear_button.pack(side=tk.RIGHT, padx=5)

    export_button = tk.Button(button_frame, text="Export Logs", command=export_logs,
                            bg="purple", fg="white", font=("Arial", 12, "bold"))
    export_button.pack(side=tk.LEFT, padx=5)

    # Main Content Frame
    content_frame = tk.Frame(root)
    content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

    # Nested Frame to Handle Side-by-Side Layout
    side_by_side_frame = tk.Frame(content_frame)
    side_by_side_frame.pack(fill=tk.BOTH, expand=True)

    # Left Frame
    left_frame = tk.Frame(side_by_side_frame)
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Right Frame
    right_frame = tk.Frame(side_by_side_frame)
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Bottom Frame
    bottom_frame = tk.Frame(content_frame)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=5, pady=5)

    # Log Frame (Left Side)
    log_frame = tk.Frame(left_frame)
    log_frame.pack(fill=tk.BOTH, expand=True)

    log_frame_title = tk.Label(log_frame, text="Log Summary", font=("Arial", 14, "bold"))
    log_frame_title.pack(anchor=tk.W, padx=5)

    log_summary_tree = ttk.Treeview(log_frame, columns=("No", "Time", "Source", "Destination", "Protocol", "Length", "Info"), show='headings')
    
    columns = ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
    for col in columns:
        log_summary_tree.heading(col, text=col)
        log_summary_tree.column(col, width=100, anchor=tk.W)  # Set a default width
    
    # Adjust column widths based on content or proportion
    def resize_columns(event):
        """Resize columns based on content and available width."""
        total_width = log_frame.winfo_width()
        min_widths = {
            "No": 30,
            "Time": 120,
            "Source": 120,
            "Destination": 120,
            "Protocol": 75,
            "Length": 75,
            "Info": 180
        }
        
        total_min_width = sum(min_widths[col] for col in columns)
        remaining_width = total_width - total_min_width
        
        # Allocate extra space to columns based on their minimum width
        column_widths = {col: min_widths[col] + (remaining_width // len(columns)) for col in columns}
        
        # Ensure minimum width is respected
        for col in columns:
            width = max(min_widths[col], column_widths[col])
            log_summary_tree.column(col, width=width, anchor=tk.W)
    
    log_summary_tree.pack(fill=tk.BOTH, expand=True)
    
    # Bind resizing to adjust column widths dynamically
    log_frame.bind('<Configure>', resize_columns)

    # Packet Details Frame (Right Side)
    details_frame = tk.Frame(right_frame)
    details_frame.pack(fill=tk.BOTH, expand=True)

    details_frame_title = tk.Label(details_frame, text="Packet Details", font=("Arial", 14, "bold"))
    details_frame_title.pack(anchor=tk.W, padx=5)
    
    details_content_frame = tk.Frame(details_frame)
    details_content_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    # Packet Details Text
    in_depth_details_text = scrolledtext.ScrolledText(details_content_frame, wrap=tk.WORD, height=10, width=40)
    in_depth_details_text.pack(fill=tk.BOTH, expand=True)
    
    metrics_frame = tk.Frame(details_content_frame)
    metrics_frame.pack(fill=tk.BOTH, expand=True)
    
    metrics_text = scrolledtext.ScrolledText(metrics_frame, wrap=tk.WORD, height=5, width=40)
    metrics_text.pack(fill=tk.BOTH, expand=True)
    
    # Visualization Frame (Bottom)
    visualization_frame = tk.Frame(bottom_frame)
    visualization_frame.pack(fill=tk.BOTH, expand=True)
    
    visualization_frame_title = tk.Label(visualization_frame, text="Visualization", font=("Arial", 14, "bold"))
    visualization_frame_title.pack(anchor=tk.W, padx=5)
    
    visualization_canvas = tk.Canvas(visualization_frame, bg="white", width=100, height=800)  # Fixed width, height can be adjusted
    visualization_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    performance_chart_canvas = tk.Canvas(visualization_frame, bg="white",width=800,height=800)
    performance_chart_canvas.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    configure_gui()
