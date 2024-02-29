import socket
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor

# Dicionário manual de serviços conhecidos associados aos números de porta
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    # Adicione mais serviços conforme necessário
}

class PortScannerApp:
    def __init__(self, master):
        self.master = master
        master.title("Port Scanner")

        self.host_label = tk.Label(master, text="Host:")
        self.host_label.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.host_entry = tk.Entry(master)
        self.host_entry.grid(row=0, column=1, padx=5, pady=5)

        self.start_port_label = tk.Label(master, text="Porta Inicial:")
        self.start_port_label.grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.start_port_entry = tk.Entry(master)
        self.start_port_entry.grid(row=1, column=1, padx=5, pady=5)

        self.end_port_label = tk.Label(master, text="Porta Final:")
        self.end_port_label.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.end_port_entry = tk.Entry(master)
        self.end_port_entry.grid(row=2, column=1, padx=5, pady=5)

        self.scan_button = tk.Button(master, text="Iniciar Escaneamento", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

        self.result_label = tk.Text(master, height=10, width=50)
        self.result_label.grid(row=4, column=0, columnspan=2, padx=5, pady=5)
        self.result_label.config(state=tk.DISABLED)

    def scan_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service_name = KNOWN_SERVICES.get(port, "Unknown")
                    self.result_label.config(state=tk.NORMAL)
                    self.result_label.insert(tk.END, f"Porta {port} ({service_name}): Aberta\n")
                    self.result_label.config(state=tk.DISABLED)
        except Exception as e:
            pass

    def scan_host(self, host, port_range):
        self.result_label.config(state=tk.NORMAL)
        self.result_label.delete("1.0", tk.END)
        self.result_label.config(state=tk.DISABLED)
        with ThreadPoolExecutor(max_workers=20) as executor:
            for port in port_range:
                executor.submit(self.scan_port, host, port)

    def start_scan(self):
        host = self.host_entry.get()
        start_port = int(self.start_port_entry.get())
        end_port = int(self.end_port_entry.get())
        port_range = range(start_port, end_port + 1)
        threading.Thread(target=self.scan_host, args=(host, port_range)).start()

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
