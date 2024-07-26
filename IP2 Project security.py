from scapy.all import *
import smtplib
from email.mime.text import MIMEText

class EmailNotifier:
    def __init__(self, smtp_server, smtp_port, email_address, email_password, recipient):
        # Initialiseer de email instellingen
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.email_address = email_address
        self.email_password = email_password
        self.recipient = recipient

    def send_email(self, subject, body):
        # Stuur een email met het opgegeven onderwerp en bericht
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.email_address
        msg['To'] = self.recipient

        server = smtplib.SMTP(self.smtp_server, self.smtp_port)
        server.starttls()
        server.login(self.email_address, self.email_password)
        server.sendmail(self.email_address, self.recipient, msg.as_string())
        server.quit()

class PacketHandler:
    def __init__(self, email_notifier):
        # Initialiseer met een EmailNotifier object
        self.email_notifier = email_notifier

    def packet_handler(self, packet):
        # Verwerk een ontvangen pakket
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(TCP):
                tcp_flags = packet[TCP].flags
                if tcp_flags & 2:  # SYN vlag (Port Scan)
                    print(f"Port scan gedetecteerd van {ip_src} naar {ip_dst}")
                    self.email_notifier.send_email(
                        "NIDS Alert - Port Scanning",
                        f"Port scan gedetecteerd van {ip_src} naar {ip_dst}"
                    )
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                if icmp_type == 8:  # ICMP Echo Request (Fingerprinting)
                    print(f"ICMP fingerprinting gedetecteerd van {ip_src} naar {ip_dst}")
                    self.email_notifier.send_email(
                        "NIDS Alert - ICMP Fingerprinting",
                        f"ICMP fingerprinting gedetecteerd van {ip_src} naar {ip_dst}"
                    )

    def start_sniffing(self):
        # Start met het sniffen van pakketten
        sniff(filter="tcp or icmp", prn=self.packet_handler, store=0)

if __name__ == "__main__":
    # Maak een EmailNotifier object aan
    email_notifier = EmailNotifier(
        smtp_server='smtp-mail.outlook.com',
        smtp_port=587,
        email_address='rzx730@hotmail.com',
        email_password='Test.Test.9988',
        recipient='speedm66200913@gmail.com'
    )
    # Maak een PacketHandler object aan en start met sniffen
    packet_handler = PacketHandler(email_notifier)
    packet_handler.start_sniffing()
