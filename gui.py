import tkinter as tk
from tkinter import ttk, messagebox
from sniffer import Sniffer, get_interfaces

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("900x600")
        self.root.resizable(True, True)

        self.sniffer = None
        self.logging_enabled=tk.BooleanVar(value=False)
        self.selected_interface=tk.StringVar()

        self._build_control_panel(),
        self._build_packet_table(),
        self._build_detail_panel()
        
    def _build_control_panel(self):
        panel=tk.Frame(self.root, pady=5, padx=5)
        panel.pack(fill="x")
        
        tk.Label(panel, text="Interfaces :").pack(side="left", padx=5)

        interfaces= get_interfaces()
        self.selected_interface.set(interfaces[0])
        menu=tk.OptionMenu(panel, self.selected_interface, *interfaces)
        menu.pack(side="left", padx=5)

        tk.Checkbutton(
            panel,
            text="Logging",
            variable=self.logging_enabled
        ).pack(side="left", padx=5)

        tk.Button(
            panel,
            text="START",
            bg="green",
            fg="white",
            command=self._start_capture
        ).pack(side="left", padx=5)


        tk.Button(
            panel,
            text="STop",
            bg="red",
            fg="white",
            command=self._stop_capture
        ).pack(side="left", padx=5)

    def _build_packet_table(self):
        frame=tk.Frame(self.root)
        frame.pack(fill="both", expand=True, padx=5, pady=5)

        columns= ("time", "ip_src", "ip_dst", "protocol", "port_src", "port_dst", "service")
        self.table=ttk.Treeview(frame, columns=columns, show="headings", height=15)

        headers={
            "time": "Heure",
            "ip_src": "IP Source", 
            "ip_dst": "IP Destination",
            "protocol": "Protocole", 
            "port_src": "Port Src",
            "port_dst":"Port Dst", 
            "service": "Service"
        }
        for col, header in headers.items():
            self.table.heading(col, text=header)
            self.table.column(col, width=120, anchor="center")
        
        scrollbar= ttk.Scrollbar(frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)

        self.table.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.table.bind("<ButtonPress-1>", self._on_packet_select)

    def _build_detail_panel(self):
        frame=tk.Frame(self.root, pady=5, padx=5)
        frame.pack(fill="x")

        tk.Label(frame, text="Détails du paquet sélectionné :", 
                font=("Arial", 10, "bold")).pack(anchor="w")
        self.detail_text=tk.Text(frame, height=8, state="disabled", bg="#f0f0f0", font=("Courier", 9))
        self.detail_text.pack(fill="x",padx=5, pady=5)
        self.log_label=tk.Label(frame, text="Log: aucun fichier actif", fg="gray", font=("Arial",8))
        self.log_label.pack(anchor="w", padx=5)

    def _start_capture(self):
        if self.sniffer is not None:
            messagebox.showwarning("Attention", "La capture est déjà en cours !")
            return
        interface= self.selected_interface.get()
        if not interface:
            messagebox.showerror("Erreur","Veuillez sélectionner une interface !")
            return
        logging=self.logging_enabled.get()
        self.sniffer = Sniffer(
            interface=interface,
            callback=self._update_table,
            logging_enabled=logging
        )
        self.sniffer.start()
        if logging:
            self.log_label.config(
                text="Log: " +self.sniffer.logger.get_log_file(),
                fg="green"
            )

    def _stop_capture(self):
        if self.sniffer is None:
            messagebox.showwarning("Attention", "Aucune capture en cours !")
            return
        self.sniffer.stop()
        self.sniffer=None
        self.log_label.config(
            text="Log: aucun fichier actif",
            fg="gray"
        )

    def _update_table(self, info):
        if info is None:
            return
        self.root.after(0, lambda: self._insert_row(info))

    def _insert_row(self, info):
        self.table.insert(
            "",
            "end",
            values=(
                info["time"],
                info["ip_src"],
                info["ip_dst"],
                info["protocol"],
                info["port_src"],
                info["port_dst"],
                info["service"],
            ),
            tags=(info["protocol"],)
        )
        self.table.tag_configure("TCP", background="#e8f4f8")
        self.table.tag_configure("UDP", background="#f8f4e8")
        self.table.tag_configure("ICMP", background="#f8e8e8")

        self.table.yview_moveto(1)

    def _on_packet_select(self, event):
            selected = self.table.selection()
            if not selected:
                return

            item = self.table.item(selected[0])
            values = item["values"]

            details = (
                "Heure      : {}\n"
                "IP Source  : {}\n"
                "IP Dest    : {}\n"
                "Protocole  : {}\n"
                "Port Src   : {}\n"
                "Port Dst   : {}\n"
                "Service    : {}\n"
            ).format(values[0], values[1], values[2],
                    values[3], values[4], values[5], values[6])

            self.detail_text.config(state="normal")
            self.detail_text.delete("1.0", "end")
            self.detail_text.insert("end", details)
            self.detail_text.config(state="disabled")

    def _on_closing(self):
        if self.sniffer is not None:
            self.sniffer.stop()
        self.root.destroy()

if __name__ =="__main__":
    root=tk.Tk()
    app= App(root)
    root.protocol("WM_DELETE_WINDOW",app._on_closing)
    root.mainloop()