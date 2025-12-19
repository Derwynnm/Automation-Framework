import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from tkinter import (
    Tk, filedialog, messagebox, ttk, StringVar,
    BooleanVar, Text, END, DISABLED, NORMAL, Scrollbar, RIGHT, Y, Frame
)
from tkinter import font as tkfont

import pandas as pd
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from paramiko.ssh_exception import SSHException

# Logging setup
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "password_update_log.txt"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.getLogger("paramiko").setLevel(logging.WARNING)

# Worker: Update or Delete User

def user_task(ip: str, platform_hint: str, cfg: dict, ui_cb):
    """Thread worker to add/update or delete a user on a device."""
    delete_mode = cfg.get("delete", False)
    user = cfg.get("user")
    passwd = cfg.get("passwd", "")

    device = {
        "device_type": "cisco_asa" if "asa" in platform_hint.lower() else "cisco_ios",
        "host": ip,
        "username": cfg.get("conn_user") or user,
        "password": cfg.get("conn_pass"),
        "secret": cfg.get("enable", ""),
        "timeout": 30,
    }

    for attempt in range(1, 4):
        try:
            conn = ConnectHandler(**device)
            if device["secret"]:
                conn.enable()

            if delete_mode:
                # Delete user flow
                conn.config_mode()
                out = conn.send_command_timing(f"no username {user}")
                if "[confirm]" in out:
                    conn.send_command_timing("\n")
                conn.exit_config_mode()
            else:
                # Create or update user
                if "asa" in platform_hint.lower():
                    cmds = [f"username {user} password {passwd} privilege 15"]
                else:
                    cmds = [f"username {user} privilege 15 secret {passwd}"]
                conn.send_config_set(cmds, delay_factor=2)

            # Commit changes
            conn.send_command_timing("write memory")
            conn.disconnect()

            # Report success without revealing CLI output
            ui_cb(f"[{ip}] Success\n", success=True)
            logging.info(f"{ip} - {'Deleted' if delete_mode else 'Updated'} user {user}")
            return

        except (NetmikoTimeoutException, NetmikoAuthenticationException, SSHException, socket.error) as e:
            ui_cb(f"[{ip}] Attempt {attempt} failed: {e}\n")
            logging.warning(f"{ip} attempt {attempt} failed: {e}")
            time.sleep(2)
        except Exception as e:
            ui_cb(f"[{ip}] Unexpected error: {e}\n")
            logging.error(f"{ip} unexpected: {e}")
            time.sleep(2)

    ui_cb(f"[{ip}] Failed after 3 attempts\n", failure=True)
    logging.error(f"{ip} - FAILED after 3 attempts")

# GUI Application

class UserManagerGUI:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("Cisco Bulk User Manager")
        self._setup_window(960, 820)
        self._setup_style()

        # Variables
        self.file_var = StringVar()
        self.user_var = StringVar()
        self.pass_var = StringVar()
        self.conn_user_var = StringVar()
        self.conn_pass_var = StringVar()
        self.enable_var = StringVar()
        self.thread_var = StringVar(value="10")
        self.del_var = BooleanVar(value=False)

        # Counters
        self.ok = 0
        self.bad = 0

        self._build_ui()

    def _setup_window(self, w: int, h: int):
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        for name in ("TkDefaultFont", "TkTextFont"):
            tkfont.nametofont(name).configure(size=10)
        style.configure("Accent.TButton", foreground="white", background="#1e81b0")
        style.map(
            "Accent.TButton",
            background=[("disabled", "#8da6b1"), ("active", "#16658c")]
        )

    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}
        frame = ttk.Frame(self.root)
        frame.pack(fill="x", **pad)

        ttk.Label(frame, text="Device list (Excel)").grid(row=0, column=0, sticky="w")
        ttk.Entry(frame, textvariable=self.file_var, width=65).grid(row=0, column=1, **pad)
        ttk.Button(frame, text="Browse", command=self._browse).grid(row=0, column=2, **pad)

        fields = [
            ("Username", self.user_var, False),
            ("New password", self.pass_var, True),
            ("Connection user", self.conn_user_var, False),
            ("Connection pass", self.conn_pass_var, True),
            ("Enable secret", self.enable_var, True),
            ("Threads", self.thread_var, False)
        ]
        self.pass_entry = None
        for i, (lbl, var, is_pwd) in enumerate(fields, start=1):
            ttk.Label(frame, text=lbl).grid(row=i, column=0, sticky="w")
            width = 8 if lbl == "Threads" else 32
            ent = ttk.Entry(frame, textvariable=var, show="*" if is_pwd else None, width=width)
            ent.grid(row=i, column=1, sticky="w", **pad)
            if lbl == "New password":
                self.pass_entry = ent

        ttk.Checkbutton(frame, text="Delete user", variable=self.del_var,
                        command=self._toggle_password_entry).grid(
            row=len(fields)+1, column=0, sticky="w", **pad
        )

        self.start_btn = ttk.Button(frame, text="Start", style="Accent.TButton",
                                    command=self._start)
        self.start_btn.grid(row=len(fields)+1, column=1, sticky="e", **pad)

        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=8, pady=(4,4))

        out_frame = Frame(self.root)
        out_frame.pack(fill="both", expand=True, padx=8, pady=8)
        self.output = Text(out_frame, wrap="word")
        sb = Scrollbar(out_frame, command=self.output.yview)
        self.output.configure(yscrollcommand=sb.set)
        self.output.pack(side="left", fill="both", expand=True)
        sb.pack(side=RIGHT, fill=Y)
        self.output.configure(state=DISABLED)

        self.status_label = ttk.Label(self.root, text="✔ 0   ✖ 0")
        self.status_label.pack(anchor="e", padx=8, pady=(0,2))
        ttk.Label(self.root, text="Developed by Derwynn McKellar", 
                  font=("TkDefaultFont", 8, "italic")).pack(
            anchor="w", padx=8, pady=(0,6)
        )

    def _browse(self):
        path = filedialog.askopenfilename(
            title="Select Excel file",
            filetypes=[("Excel files","*.xlsx *.xls")]
        )
        if path:
            self.file_var.set(path)

    def _toggle_password_entry(self):
        if self.del_var.get():
            self.pass_entry.state(["disabled"])
        else:
            self.pass_entry.state(["!disabled"])

    def _append(self, msg, *, success=False, failure=False):
        self.output.configure(state=DISABLED)
        self.output.configure(state=NORMAL)
        self.output.insert(END, msg)
        self.output.see(END)
        self.output.configure(state=DISABLED)
        if success:
            self.ok += 1
        if failure:
            self.bad += 1
        self.status_label.configure(text=f"✔ {self.ok}   ✖ {self.bad}")

    def _start(self):
        if not self.file_var.get():
            self._append("[!] Select an Excel file.\n")
            return
        if not self.user_var.get():
            self._append("[!] Username required.\n")
            return
        if not self.del_var.get() and not self.pass_var.get():
            self._append("[!] Password required unless deleting.\n")
            return
        if self.del_var.get():
            if not messagebox.askyesno(
                    "Confirm deletion",
                    f"Delete user '{self.user_var.get()}' from all devices?"
            ):
                return

        self.start_btn.state(["disabled"])
        self.progress.start(10)
        threading.Thread(target=self._run, daemon=True).start()

    def _finish(self):
        self.progress.stop()
        self.start_btn.state(["!disabled"])

    def _run(self):
        try:
            df = pd.read_excel(self.file_var.get()).dropna(subset=["IP Address"])
        except Exception as exc:
            self._append(f"[!] Excel load error: {exc}\n")
            self._finish()
            return

        self.ok = self.bad = 0
        self.status_label.configure(text="✔ 0   ✖ 0")

        cfg = {
            "user": self.user_var.get(),
            "passwd": self.pass_var.get(),
            "conn_user": self.conn_user_var.get() or self.user_var.get(),
            "conn_pass": self.conn_pass_var.get(),
            "enable": self.enable_var.get(),
            "delete": self.del_var.get()
        }

        threads = int(self.thread_var.get() or 10)
        self._append(f"[*] Running on {len(df)} devices with {threads} threads...\n")

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [
                pool.submit(
                    user_task,
                    str(r["IP Address"]).strip(),
                    str(r.get("DeviceType", "")),
                    cfg,
                    self._append
                )
                for _, r in df.iterrows()
            ]
            for _ in as_completed(futures):
                pass

        self._append("[*] Completed.\n")
        self._finish()

# Entry point

def main():
    root = Tk()
    try:
        root.iconbitmap("command.ico")
    except Exception:
        pass
    UserManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
