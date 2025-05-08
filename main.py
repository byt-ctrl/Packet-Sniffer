import scapy.all as scapy
import socket
import dpkt
import customtkinter as ctk
from tkinter import ttk
from datetime import datetime
import logging
import threading
import re

# configure logging
logging.basicConfig(
    filename='packet_sniffer.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class PacketSniffer :

    def __init__(self) :
        """initialize the packet sniffer with a GUI."""
        self.packets=[]
        self.is_sniffing=False
        self.root=ctk.CTk()
        self.root.title("Packet Sniffer")
        self.root.geometry("1000x600")
        self.root.minsize(800,500)

        # set customtkinter appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.setup_gui()

    def setup_gui(self) :

        """set up the main GUI with controls and treeview."""
        main_frame=ctk.CTkFrame(self.root,corner_radius=0)
        main_frame.pack(fill="both",expand=True)

        # header
        ctk.CTkLabel(
            main_frame,
            text="Packet Sniffer",
            font=ctk.CTkFont(size=24,weight="bold")
        ).pack(anchor="w",pady=10,padx=20)

        # Control frame
        control_frame=ctk.CTkFrame(main_frame,fg_color="transparent")
        control_frame.pack(fill="x",pady=10,padx=20)

        # sniff button
        self.sniff_button=ctk.CTkButton(
            control_frame,
            text="Start Sniffing",
            command=self.toggle_sniffing,
            font=ctk.CTkFont(size=12),
            width=150
        )
        self.sniff_button.pack(side="left", padx=10)

        # filter inputs
        ctk.CTkLabel(
            control_frame,
            text="Source IP:",
            font=ctk.CTkFont(size=12)
        ).pack(side="left", padx=5)
        self.source_entry=ctk.CTkEntry(
            control_frame,
            placeholder_text="e.g. 192.168.1.1",
            width=150
        )
        self.source_entry.pack(side="left",padx=5)

        ctk.CTkLabel(
            control_frame,
            text="Destination IP :",
            font=ctk.CTkFont(size=12)
        ).pack(side="left",padx=5)
        self.dest_entry=ctk.CTkEntry(
            control_frame,
            placeholder_text="e.g. 8.8.8.8",
            width=150
        )
        self.dest_entry.pack(side="left",padx=5)

        ctk.CTkLabel(
            control_frame,
            text="Protocol :",
            font=ctk.CTkFont(size=12)
        ).pack(side="left",padx=5)
        self.protocol_var=ctk.StringVar(value="All")
        protocol_combo=ctk.CTkComboBox(
            control_frame,
            values=["All","TCP","UDP","ICMP"],
            variable=self.protocol_var,
            width=100
        )
        protocol_combo.pack(side="left",padx=5)

        ctk.CTkButton(
            control_frame,
            text="Apply Filters",
            command=self.apply_filters,
            font=ctk.CTkFont(size=12)
        ).pack(side="left",padx=10)

        # packet treeview (using ttk.Treeview)
        style=ttk.Style()
        style.configure("Treeview",background="#2B2B2B",foreground="white",fieldbackground="#2B2B2B")
        style.configure("Treeview.Heading", background="#3C3C3C", foreground="white")
        style.map("Treeview",background=[('selected','#1F6AA5')])

        self.packet_tree=ttk.Treeview(
            main_frame,
            columns=("Timestamp","Source IP","Destination IP","Protocol","Length"),
            show="headings",
            height=20,
            style="Treeview"
        )
        for col in self.packet_tree["columns"] :
            self.packet_tree.heading(col,text=col)
            self.packet_tree.column(col,width=150,anchor="center")
        self.packet_tree.pack(fill="both",expand=True,padx=20,pady=10)

        # status label
        self.status_var=ctk.StringVar(value="Status : Idle")
        ctk.CTkLabel(
            main_frame,
            textvariable=self.status_var,
            font=ctk.CTkFont(size=12)
        ).pack(anchor="w", padx=20, pady=5)

    def show_notification(self,message) :

        """ display a temporary notification."""
        notification=ctk.CTkLabel(
            self.root,
            text=message,
            font=ctk.CTkFont(size=12),
            text_color="white",
            bg_color="#4CAF50",
            corner_radius=10,
            padx=20,
            pady=10
        )
        notification.place(relx=0.5,rely=0.1,anchor="n")
        self.root.after(3000,notification.destroy)

    def toggle_sniffing(self) :
        """start or stop packet sniffing."""
        if not self.is_sniffing :
            self.is_sniffing=True
            self.sniff_button.configure(text="Stop Sniffing",fg_color="#EF4444",hover_color="#DC2626")
            self.status_var.set("Status: Sniffing......")
            self.packets=[]
            threading.Thread(target=self.sniff_packets, daemon=True).start()
        else:
            self.is_sniffing = False
            self.sniff_button.configure(text="Start Sniffing",fg_color="#1F6AA5",hover_color="#144870")
            self.status_var.set("Status: Idle")
            self.log_packets()

    def sniff_packets(self) :
        """capture packets using scapy."""
        try:
            while self.is_sniffing:
                packet = scapy.sniff(count=1, timeout=1)
                if packet:
                    self.packets.extend(packet)
                    self.analyze_packets(packet)
            logging.info("Packet sniffing stopped")
        except PermissionError:
            self.root.after(0, lambda: ctk.CTkMessageBox(
                title="Error",
                message="Run as administrator to capture packets",
                icon="cancel"
            ).show())
            self.is_sniffing = False
            self.root.after(0, lambda: self.sniff_button.configure(
                text="Start Sniffing",
                fg_color="#1F6AA5",
                hover_color="#144870"
            ))
            self.root.after(0, lambda: self.status_var.set("Status: Idle"))
            logging.error("Permission denied: Run as administrator")
        except Exception as e:
            self.root.after(0, lambda: ctk.CTkMessageBox(
                title="Error",
                message=f"Sniffing error: {e}",
                icon="cancel"
            ).show())
            self.is_sniffing = False
            self.root.after(0, lambda: self.sniff_button.configure(
                text="Start Sniffing",
                fg_color="#1F6AA5",
                hover_color="#144870"
            ))
            self.root.after(0, lambda: self.status_var.set("Status: Idle"))
            logging.error(f"Sniffing error: {e}")

    def filter_packets(self, packets, protocol=None, source=None, destination=None):
        """Filter packets based on protocol, source, and destination."""
        filtered_packets = []
        protocol_map = {
            "TCP": dpkt.ip.IP_PROTO_TCP,
            "UDP": dpkt.ip.IP_PROTO_UDP,
            "ICMP": dpkt.ip.IP_PROTO_ICMP
        }
        protocol_num = protocol_map.get(protocol) if protocol and protocol != "All" else None

        for packet in packets:
            try:
                eth = dpkt.ethernet.Ethernet(bytes(packet))
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    if protocol_num and ip.p != protocol_num:
                        continue
                    src_ip = socket.inet_ntoa(ip.src)
                    dst_ip = socket.inet_ntoa(ip.dst)
                    if source and src_ip != source:
                        continue
                    if destination and dst_ip != destination:
                        continue
                    filtered_packets.append(packet)
            except Exception as e:
                logging.warning(f"Error filtering packet: {e}")
                continue
        return filtered_packets

    def log_packets(self, filename='packets.log'):
        """Log packet details to a file."""
        try:
            with open(filename, 'a') as f:
                for packet in self.packets:
                    try:
                        eth = dpkt.ethernet.Ethernet(bytes(packet))
                        ip = eth.data
                        if isinstance(ip, dpkt.ip.IP):
                            f.write(
                                f"[{datetime.fromtimestamp(packet.time)}] "
                                f"Source: {socket.inet_ntoa(ip.src)}, "
                                f"Destination: {socket.inet_ntoa(ip.dst)}, "
                                f"Protocol: {ip.p}, Length: {ip.len}\n"
                            )
                    except Exception as e:
                        logging.warning(f"Error logging packet: {e}")
            logging.info(f"Packets logged to {filename}")
        except Exception as e:
            self.root.after(0, lambda: ctk.CTkMessageBox(
                title="Error",
                message=f"Logging error: {e}",
                icon="cancel"
            ).show())
            logging.error(f"Logging error: {e}")

    def analyze_packets(self, packets):
        """Analyze packets and update the GUI."""
        detailed_packets = []
        for packet in packets:
            try:
                eth = dpkt.ethernet.Ethernet(bytes(packet))
                ip = eth.data
                if isinstance(ip, dpkt.ip.IP):
                    protocol_map = {
                        dpkt.ip.IP_PROTO_TCP: "TCP",
                        dpkt.ip.IP_PROTO_UDP: "UDP",
                        dpkt.ip.IP_PROTO_ICMP: "ICMP"
                    }
                    protocol = protocol_map.get(ip.p, str(ip.p))
                    packet_info = {
                        'source_ip': socket.inet_ntoa(ip.src),
                        'destination_ip': socket.inet_ntoa(ip.dst),
                        'protocol': protocol,
                        'length': ip.len,
                        'timestamp': datetime.fromtimestamp(packet.time).strftime("%Y-%m-%d %H:%M:%S")
                    }
                    detailed_packets.append(packet_info)
            except Exception as e:
                logging.warning(f"Error analyzing packet: {e}")
                continue
        self.display_live_packets(detailed_packets)

    def display_live_packets(self, packets):
        """Display packets in the GUI treeview."""
        for packet in packets:
            self.update_tree(packet)

    def update_tree(self, packet_info):
        """Update the treeview with packet information."""
        self.packet_tree.insert("", "end", values=(
            packet_info['timestamp'],
            packet_info['source_ip'],
            packet_info['destination_ip'],
            packet_info['protocol'],
            packet_info['length']
        ))
        # Auto-scroll to the latest packet
        self.packet_tree.yview_moveto(1)

    def apply_filters(self):
        """Apply filters and update the treeview."""
        source = self.source_entry.get().strip()
        destination = self.dest_entry.get().strip()
        protocol = self.protocol_var.get()

        # Validate IP addresses
        ip_pattern = r'^(?:\d{1,3}\.){3}\d{1,3}$'
        if source and not re.match(ip_pattern, source):
            ctk.CTkMessageBox(title="Error", message="Invalid source IP", icon="cancel")
            return
        if destination and not re.match(ip_pattern, destination):
            ctk.CTkMessageBox(title="Error", message="Invalid destination IP", icon="cancel")
            return

        # clear current treeview
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)

        # filter packets
        filtered_packets = self.filter_packets(self.packets, protocol, source, destination)
        self.analyze_packets(filtered_packets)
        self.show_notification("Filters applied successfully")
        logging.info(f"Filters applied: protocol={protocol}, source={source}, destination={destination}")

    def run(self):
        
        """run the application."""
        try:
            self.root.mainloop()
        except Exception as e:
            logging.error(f"Application error: {e}")
            self.root.after(0, lambda: ctk.CTkMessageBox(
                title="Error",
                message=f"Application error: {e}",
                icon="cancel"
            ).show())

if __name__=='__main__':
    try:
        sniffer=PacketSniffer()
        sniffer.run()
    except KeyboardInterrupt:
        logging.info("Application terminated by user")
    except Exception as e:
        logging.error(f"Startup error: {e}")
        print(f"Error: {e}")