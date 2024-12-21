from tkinter import messagebox, ttk
from PIL import Image
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from ipwhois import IPWhois
from CTkMenuBar import *
from modules.tooltip import ToolTip
from scripts.shodan_api import shodan_scan, host_info
import customtkinter as ctk
import requests
import threading
import os
import subprocess
import socket
import tkinter as tk
import re
import whois
import json
from datetime import datetime
import os
import sys

requests.packages.urllib3.disable_warnings()

class ReconX:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.title("ReconX v1.1")
        self.window.geometry("1025x575")
        self.window.configure(bg="#000000")
        self.window.configure(fg_color="#000000")
        # Add window icon (add this after window creation)
        icon_photo = tk.PhotoImage(file="icons/logo.png")
        self.window.iconphoto(False, icon_photo)
        self.window.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        icon_path = os.path.join(os.path.dirname(__file__), "icons")

        # Update other image loads
        icon_photo = tk.PhotoImage(file=("icons/logo.png"))
        self.window.iconphoto(False, icon_photo)
        self.stop_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "stop.png")), size=(20, 20))
        self.start_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "start.png")), size=(20, 20))
        self.clear_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "clear.png")), size=(20, 20))
        self.logo_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "logo.png")), size=(100, 100))
        self.home_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "home.png")), size=(30, 30))
        self.settings_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "settings.png")), size=(30, 30))
        self.subdomains_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "domains.png")), size=(30, 30))
        self.asn_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "asn.png")), size=(30, 30))
        self.headers_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "headers.png")), size=(30, 30))
        self.javascript_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "javascript.png")), size=(30, 30))
        self.links_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "links.png")), size=(30, 30))
        self.whois_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "whois.png")), size=(30, 30))
        self.shodan_image = ctk.CTkImage(Image.open(os.path.join(icon_path, "shodan.png")), size=(30, 30))
        
        def about():
            messagebox.showinfo("Author", "ReconX by c0d3ninja")

        def update():
            """Check for and apply updates with progress indication"""
            try:
                self.progress_bar.start()
                self.progress_label.configure(text="Checking for updates...")
                self.button.configure(state=ctk.DISABLED)
                self.clear_button.configure(state=ctk.DISABLED)

                # Fetch first to check for updates
                fetch_result = subprocess.run(
                    ["git", "fetch"], 
                    check=True, 
                    capture_output=True, 
                    text=True
                )

                # Check if we're behind the remote
                status_result = subprocess.run(
                    ["git", "status", "-uno"],
                    check=True,
                    capture_output=True,
                    text=True
                )

                if "Your branch is behind" in status_result.stdout:
                    # There are updates available
                    self.progress_label.configure(text="Downloading updates...")
                    
                    # Perform the actual update
                    pull_result = subprocess.run(
                        ["git", "pull"],
                        check=True,
                        capture_output=True,
                        text=True
                    )

                    if pull_result.returncode == 0:
                        self.progress_label.configure(text="Update completed successfully!")
                    else:
                        self.progress_label.configure(text="Update failed. Please try again.")
                else:
                    self.progress_label.configure(text="Already up to date!")

            except subprocess.CalledProcessError as e:
                self.progress_label.configure(text=f"Update error: {str(e)}")
            except Exception as e:
                self.progress_label.configure(text=f"Unexpected error: {str(e)}")
            finally:
                self.progress_bar.stop()
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)

        style = ttk.Style()
        style.configure("Treeview", background="#000000", fieldbackground="#000000", foreground="white", font=("Arial", 14))
        style.map("Treeview", background=[("selected", "#14375e")])

        file_menu = CTkMenuBar(master=self.window, bg_color="#000000")
        file_button = file_menu.add_cascade("File")
        file_button_help =  file_menu.add_cascade("Help")

        submenu = CustomDropdownMenu(widget=file_button, bg_color="#000000")
        submenu.add_option("Update", command=update)
        submenu.add_option("Exit", command=exit)

        helpmenu = CustomDropdownMenu(widget=file_button_help, bg_color="#000000")
        helpmenu.add_option("About", command=about)

        self.frame = ctk.CTkFrame(self.window, border_width=0, width=780, height=430, fg_color="#000000", border_color="#000000")
        self.frame.pack(padx=10, pady=10)

        self.frame_top = ctk.CTkFrame(self.window, width=780, height=430, fg_color="#000000", border_width=1, border_color="white")
        self.frame_top.pack(side=ctk.RIGHT, padx=10, pady=10)

        self.menu_frame = ctk.CTkFrame(self.frame_top, width=750, height=360, fg_color="#000000")
        self.menu_frame.pack(side=ctk.TOP, padx=10, pady=10)

        self.settings_frame = ctk.CTkFrame(self.window, width=750, height=360, border_width=1, border_color="white", fg_color="#000000")
        self.settings_frame.pack(side=ctk.TOP, padx=10, pady=10, fill="both", expand=True)
        self.settings_frame.grid_propagate(False)

        self.progress_bar = ctk.CTkProgressBar(self.frame_top, width=700, height=7, corner_radius=10)
        self.progress_bar.pack(side=ctk.BOTTOM, padx=10, pady=10)

        self.progress_label = ctk.CTkLabel(self.frame_top, text="Waiting for input...", font=("Arial", 14), text_color="white")
        self.progress_label.pack(side=ctk.BOTTOM, padx=10, pady=10)

        self.status_frame = ctk.CTkFrame(self.frame_top, width=700, fg_color="#000000")
        self.status_frame.pack(side=ctk.BOTTOM, padx=10, pady=0)

        self.threads_label = ctk.CTkLabel(self.status_frame, text="Threads: 0", font=("Arial", 14), text_color="white")
        self.threads_label.pack(side=ctk.LEFT, padx=10, pady=10)

        self.proxy_label = ctk.CTkLabel(self.status_frame, text="Proxy: None", font=("Arial", 14), text_color="white")
        self.proxy_label.pack(side=ctk.LEFT, padx=10, pady=10)

        self.user_agent_label = ctk.CTkLabel(self.status_frame, text="User-Agent: None", font=("Arial", 14), text_color="white")
        self.user_agent_label.pack(side=ctk.LEFT, padx=10, pady=10)

        self.entry = ctk.CTkEntry(self.frame, width=580, height=40, placeholder_text="Enter a domain", font=("Arial", 14), text_color="white", bg_color="#000000", fg_color="#000000")
        self.entry.pack(side=ctk.LEFT, padx=10, pady=10)

        self.start_port_frame = ctk.CTkFrame(self.settings_frame, width=40, height=360, fg_color="#000000")
        self.start_port_frame.pack(side=ctk.BOTTOM, padx=10, pady=10)
        self.start_port_frame.grid_propagate(False)

        self.startport_entry = ctk.CTkEntry(self.start_port_frame, width=50, height=9, placeholder_text="1", font=("Arial", 14), text_color="white", bg_color="#000000", fg_color="#000000")
        self.startport_entry.pack(side=ctk.LEFT, padx=10, pady=10)
        self.endport_entry = ctk.CTkEntry(self.start_port_frame, width=50, height=9, placeholder_text="1024", font=("Arial", 14), text_color="white", bg_color="#000000", fg_color="#000000")
        self.endport_entry.pack(side=ctk.LEFT, padx=10, pady=10)

        self.is_scanning = False
        self.stop_button = ctk.CTkButton(self.frame, width=25, height=40, text="", 
                                        font=("Arial", 14), text_color="white",
                                        command=self.stop_scan, image=self.stop_image,
                                        corner_radius=100, fg_color="#14375e")
        self.stop_button.pack(side=ctk.RIGHT, padx=10, pady=10)
        self.stop_button.configure(state=ctk.DISABLED)

        self.button = ctk.CTkButton(self.frame, width=25, height=40, text="", font=("Arial", 14), text_color="white", 
                                    command=self.check_selected, image=self.start_image, corner_radius=100, fg_color="#14375e")
        self.button.pack(side=ctk.RIGHT, padx=10, pady=10)

        self.clear_button = ctk.CTkButton(self.frame, width=25, height=40, text="", font=("Arial", 14), text_color="white", 
                                          command=self.clear_textbox, image=self.clear_image, corner_radius=100, fg_color="#14375e")
        self.clear_button.pack(side=ctk.RIGHT, padx=10, pady=10)


        self.waiting_frames = ["Waiting for input", "Waiting for input.", "Waiting for input..", "Waiting for input..."]
        self.current_frame = 0
        self.animate_waiting()

        #self.textbox = ctk.CTkTextbox(self.frame_top, width=760, height=360, font=("Arial", 14), text_color="white", bg_color="#000000", fg_color="#000000")
        #self.textbox.pack(side=ctk.LEFT, padx=10, pady=10)

        self.menu = ctk.CTkOptionMenu(self.frame, width=100, height=25, values=["Headers", "Port Scan", "ASN", "Subdomains", "Links", "JavaScript", "Whois", "Shodan"], font=("Arial", 14), text_color="white", 
                                      bg_color="#000000", fg_color="#000000")
        self.menu.pack(side=ctk.RIGHT, padx=10, pady=10)

        self.tabview = ctk.CTkTabview(self.frame_top, width=760, height=360, text_color="white", fg_color="#000000", 
                                      border_width=0, corner_radius=0, segmented_button_selected_color="#000000", segmented_button_selected_hover_color="#000000", segmented_button_unselected_color="#000000", 
                                      segmented_button_unselected_hover_color="#000000")
        self.tabview.pack(side=ctk.LEFT, padx=10, pady=10)
        self.tabview.add("Home")
        self.tabview.add("Settings")
        self.tabview.add("Subdomains")
        self.tabview.add("ASN")
        self.tabview.add("Headers")
        self.tabview.add("Links")
        self.tabview.add("JavaScript")
        self.tabview.add("Whois")
        self.tabview.add("Shodan")
        self.tabview._segmented_button.configure(border_width=0, fg_color="#000000", text_color="#000000")

        self.port_services_tabview = ctk.CTkTabview(self.settings_frame, width=200, height=500, text_color="white", fg_color="#000000")
        self.port_services_tabview.pack(side=ctk.TOP, padx=10, pady=10)
        self.port_services_tabview.add("Ports")
        self.port_services_tabview.add("Services")
        self.port_services_tabview._segmented_button.configure(border_width=0, fg_color="#000000", text_color="#000000")

        #self.scrollbar = ctk.CTkScrollbar(self.frame2, width=15, height=360, orientation="vertical")
        #self.scrollbar.pack(side=ctk.RIGHT, fill=ctk.Y)
        #self.textbox.configure(yscrollcommand=self.scrollbar.set)
        #self.scrollbar.configure(command=self.textbox.yview)

        self.home_label = ctk.CTkLabel(self.tabview.tab("Home"), text="", font=("Arial", 25), text_color="white", image=self.logo_image, compound="top")
        self.home_label.pack(side=ctk.TOP, padx=10, pady=10)

        #self.home_label = ctk.CTkLabel(self.tabview.tab("Home"), text="WELCOME TO RECONX", font=("Arial", 25), text_color="white")
        #self.home_label.pack(side=ctk.TOP, padx=10, pady=10)

        # Thread Settings
        self.thread_settings_frame = ctk.CTkFrame(self.tabview.tab("Settings"), fg_color="#000000")
        self.thread_settings_frame.pack(side=ctk.TOP, fill="x", padx=10, pady=5)

        self.thread_controls_frame = ctk.CTkFrame(self.thread_settings_frame, fg_color="#000000")
        self.thread_controls_frame.pack(side=ctk.TOP, padx=5, pady=5)

        self.proxy_controls_frame = ctk.CTkFrame(self.thread_settings_frame, fg_color="#000000")
        self.proxy_controls_frame.pack(side=ctk.TOP, padx=5, pady=5)

        self.ua_controls_frame = ctk.CTkFrame(self.thread_settings_frame, fg_color="#000000")
        self.ua_controls_frame.pack(side=ctk.TOP, padx=5, pady=5)

        ua_label = ctk.CTkLabel(self.ua_controls_frame, text="User-Agent:", text_color="white")
        ua_label.pack(side=ctk.LEFT, padx=10)
        self.ua_entry = ctk.CTkEntry(self.ua_controls_frame, width=125, height=25, fg_color="#000000")
        self.ua_entry.pack(side=ctk.LEFT, padx=10)


        proxy_label = ctk.CTkLabel(self.proxy_controls_frame, text="Proxy:", text_color="white")
        proxy_label.pack(side=ctk.LEFT, padx=27)
        self.proxy_entry = ctk.CTkEntry(self.proxy_controls_frame, width=125, height=25, fg_color="#000000")
        self.proxy_entry.pack(side=ctk.LEFT, padx=27)


        # Add save results checkbox
        self.save_results_var = ctk.BooleanVar(value=False)
        self.save_results_checkbox = ctk.CTkCheckBox(
            self.thread_settings_frame,
            text="Save Results",
            variable=self.save_results_var,
            text_color="white",
            fg_color="#14375e",
            hover_color="#1c4b7e"
        )
        self.save_results_checkbox.pack(side=ctk.TOP, padx=10, pady=5)

        self.thread_label = ctk.CTkLabel(self.thread_controls_frame, text="Max Threads:", text_color="white")
        self.thread_label.pack(side=ctk.LEFT, padx=5)
        self.thread_entry = ctk.CTkEntry(self.thread_controls_frame, width=125, height=25, fg_color="#000000")
        self.thread_entry.insert(0, "10")  # Default threads
        self.thread_entry.pack(side=ctk.LEFT, padx=5)

        
        

        self.subdomain_tree = ttk.Treeview(self.tabview.tab("Subdomains"), columns=("Domain", "Status Code", "IP", "Server"), show="headings", style="Treeview")
        self.subdomain_tree.heading("Domain", text="Domain")
        self.subdomain_tree.heading("Status Code", text="Status Code")  # Match the column name
        self.subdomain_tree.heading("IP", text="IP")
        self.subdomain_tree.heading("Server", text="Server")
        # Optional: Set column widths
        self.subdomain_tree.column("Domain", width=150)
        self.subdomain_tree.column("Status Code", width=70)
        self.subdomain_tree.column("IP", width=100)
        self.subdomain_tree.column("Server", width=100)
        # Add scrollbar 
        self.subdomain_scrollbar = ttk.Scrollbar(self.tabview.tab("Subdomains"), orient="vertical", command=self.subdomain_tree.yview)
        self.subdomain_tree.configure(yscrollcommand=self.subdomain_scrollbar.set)
        # Pack the Treeview and scrollbar
        self.subdomain_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.subdomain_scrollbar.pack(side="right", fill="y")

        self.ports_tree = ttk.Treeview(self.port_services_tabview.tab("Ports"), columns=("Ports"), show="headings", style="Treeview")
        self.ports_tree.heading("Ports", text="Ports")

        # Optional: Set column widths
        self.ports_tree.column("Ports", width=150, anchor="center")
        self.ports_tree.pack(side="right", fill="both")

        self.services_tree = ttk.Treeview(self.port_services_tabview.tab("Services"), columns=("Services"), show="headings", style="Treeview")
        self.services_tree.heading("Services", text="Services")
        self.services_tree.column("Services", anchor="center")

        # Optional: Set column widths
        self.services_tree.column("Services", width=150)
        self.services_tree.pack(side="right", fill="both")

        # ASN Tree
        self.asn_tree = ttk.Treeview(self.tabview.tab("ASN"), 
                                   columns=("Property", "Value"), 
                                   show="headings", 
                                   style="Treeview")
        self.asn_tree.heading("Property", text="Property")
        self.asn_tree.heading("Value", text="Value")
        self.asn_tree.pack(side="left", fill="both", expand=True)

        # Headers Tree
        self.headers_tree = ttk.Treeview(self.tabview.tab("Headers"), 
                                   columns=("Value", "Key"), 
                                   show="headings", 
                                   style="Treeview")
        self.headers_tree.heading("Value", text="Value")
        self.headers_tree.heading("Key", text="Key")
        self.headers_tree.pack(side="left", fill="both", expand=True)

        self.headers_scrollbar = ttk.Scrollbar(self.tabview.tab("Headers"), orient="vertical", command=self.headers_tree.yview)
        self.headers_tree.configure(yscrollcommand=self.headers_scrollbar.set)
        self.headers_scrollbar.pack(side="right", fill="y")

        # Javascript Tree
        self.javascript_tree = ttk.Treeview(self.tabview.tab("JavaScript"), 
                                   columns=("Files", "Status"), 
                                   show="headings", 
                                   style="Treeview")
        self.javascript_tree.heading("Files", text="Files")
        self.javascript_tree.heading("Status", text="Status")
        self.javascript_tree.pack(side="left", fill="both", expand=True)
        self.javascript_tree.column("Status", anchor="center")
        self.javascript_tree.column("Files", width=275)
        self.javascript_scrollbar = ttk.Scrollbar(self.tabview.tab("JavaScript"), orient="vertical", command=self.javascript_tree.yview)
        self.javascript_tree.configure(yscrollcommand=self.javascript_scrollbar.set)
        self.javascript_scrollbar.pack(side="right", fill="y")


        # Links Tree
        self.links_tree = ttk.Treeview(self.tabview.tab("Links"), 
                                   columns=("Links"), 
                                   show="headings", 
                                   style="Treeview")
        self.links_tree.heading("Links", text="Links")
        self.links_tree.pack(side="left", fill="both", expand=True)
        self.links_tree.column("Links", width=250)
        self.links_scrollbar = ttk.Scrollbar(self.tabview.tab("Links"), orient="vertical", command=self.links_tree.yview)
        self.links_tree.configure(yscrollcommand=self.links_scrollbar.set)
        self.links_scrollbar.pack(side="right", fill="y")

        # WHOIS Tree
        self.whois_tree = ttk.Treeview(self.tabview.tab("Whois"), 
                                   columns=("Content", "Value"), 
                                   show="headings", 
                                   style="Treeview")
        self.whois_tree.heading("Content", text="Content")
        self.whois_tree.heading("Value", text="Value")
        self.whois_tree.pack(side="left", fill="both", expand=True)
        self.whois_tree.column("Content", width=150)
        self.whois_tree.column("Value", width=250)
        self.whois_scrollbar = ttk.Scrollbar(self.tabview.tab("Whois"), orient="vertical", command=self.whois_tree.yview)
        self.whois_tree.configure(yscrollcommand=self.whois_scrollbar.set)
        self.whois_scrollbar.pack(side="right", fill="y")

        # Shodan Tree
        self.shodan_tree = ttk.Treeview(self.tabview.tab("Shodan"), 
                                   columns=("IP", "ORG", "PORTS"), 
                                   show="headings", 
                                   style="Treeview")
        self.shodan_tree.heading("IP", text="IP")
        self.shodan_tree.heading("ORG", text="ORG")
        self.shodan_tree.heading("PORTS", text="PORTS")
        self.shodan_tree.pack(side="left", fill="both", expand=True)
        self.shodan_tree.column("IP", width=150)
        self.shodan_tree.column("ORG", width=150)
        self.shodan_tree.column("PORTS", width=150)
        self.shodan_scrollbar = ttk.Scrollbar(self.tabview.tab("Shodan"), orient="vertical", command=self.shodan_tree.yview)
        self.shodan_tree.configure(yscrollcommand=self.shodan_scrollbar.set)
        self.shodan_scrollbar.pack(side="right", fill="y")


        self.home_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.home_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Home"))
        self.home_button.pack(side=ctk.LEFT, padx=10, pady=10)


        self.settings_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.settings_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Settings"))
        self.settings_button.pack(side=ctk.LEFT, padx=10, pady=10)


        self.subdomains_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.subdomains_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Subdomains"))
        self.subdomains_button.pack(side=ctk.LEFT, padx=10, pady=10)

  
        self.asn_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.asn_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("ASN"))
        self.asn_button.pack(side=ctk.LEFT, padx=10, pady=10)
   
        self.headers_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.headers_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Headers"))
        self.headers_button.pack(side=ctk.LEFT, padx=10, pady=10)

   
        self.javascript_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.javascript_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("JavaScript"))
        self.javascript_button.pack(side=ctk.LEFT, padx=10, pady=10)

   
        self.links_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.links_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Links"))
        self.links_button.pack(side=ctk.LEFT, padx=10, pady=10)

    
        self.whois_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.whois_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Whois"))
        self.whois_button.pack(side=ctk.LEFT, padx=10, pady=10)

        self.shodan_button = ctk.CTkButton(self.menu_frame, width=20, height=20, text="", font=("Arial", 14), image=self.shodan_image, 
                                               corner_radius=100, fg_color="transparent", text_color="white", command=lambda: self.switch_tab("Shodan"))
        self.shodan_button.pack(side=ctk.LEFT, padx=10, pady=10)

        self.thread_tooltip = ToolTip(self.thread_entry, "Max Threads")
        self.proxy_tooltip = ToolTip(self.proxy_entry, "Proxy")
        self.ua_tooltip = ToolTip(self.ua_entry, "User-Agent")

        self.update_status()

    def stop_scan(self):
        """Stop any running scan"""
        self.is_scanning = False
        self.progress_label.configure(text="Scan stopped by user")
        self.stop_button.configure(state=ctk.DISABLED)
        self.button.configure(state=ctk.NORMAL)
        self.clear_button.configure(state=ctk.NORMAL)

    def start_scan(self):
        """Common method to start any scan"""
        self.is_scanning = True
        self.button.configure(state=ctk.DISABLED)
        self.clear_button.configure(state=ctk.DISABLED)
        self.stop_button.configure(state=ctk.NORMAL)

    def update_status(self):
        """Update the status labels"""
        if self.thread_entry.get():
            self.thread_tooltip.update_text(self.thread_entry.get())
            self.threads_label.configure(text=f"Threads: {self.thread_entry.get()}")
        else:
            self.thread_tooltip.update_text("Max Threads")
            self.threads_label.configure(text=f"Threads: {self.thread_entry.get()}")

        if self.proxy_entry.get():
            self.proxy_tooltip.update_text(self.proxy_entry.get())
            self.proxy_label.configure(text=f"Proxy: {self.proxy_entry.get()}")
        else:
            self.proxy_tooltip.update_text("Proxy")
            self.proxy_label.configure(text=f"Proxy: {self.proxy_entry.get()}")

        if self.ua_entry.get():
            user_agent = self.ua_entry.get() 
            user_agent_display = user_agent.split(" ")[0]
            self.ua_tooltip.update_text(user_agent)
            self.user_agent_label.configure(text=f"User-Agent: {user_agent_display}")
        else:
            self.ua_tooltip.update_text("User-Agent")
            self.user_agent_label.configure(text=f"User-Agent: {self.ua_entry.get()}")

        self.window.after(500, self.update_status)


    def animate_waiting(self):
        """Animate the waiting text"""
        if self.progress_label.cget("text").startswith("Waiting for input"):
            self.current_frame = (self.current_frame + 1) % len(self.waiting_frames)
            self.progress_label.configure(text=self.waiting_frames[self.current_frame])
        self.window.after(500, self.animate_waiting) 

    def switch_tab(self, tab_name):
        """Switch to the specified tab"""
        try:
            self.tabview.set(tab_name)
            
            # Optional: Update button appearances to show active state
            buttons = {
                "Home": self.home_button,
                "Subdomains": self.subdomains_button,
                "ASN": self.asn_button,
                "Headers": self.headers_button,
                "Links": self.links_button,
                "JS Files": self.javascript_button,
                "Whois": self.whois_button,
                "Shodan": self.shodan_button
            }
            
            # Reset all buttons to default state
            for button in buttons.values():
                button.configure(fg_color="transparent")
            
            # Highlight active button
            if tab_name in buttons:
                buttons[tab_name].configure(fg_color="#14375e")
                
        except Exception as e:
            print(f"Error switching to tab {tab_name}: {e}")

    def check_selected(self):
        if self.menu.get() == "Headers":
            self.headers_thread()
        elif self.menu.get() == "Subdomains":
            self.subdomain_thread()
        elif self.menu.get() == "Port Scan":
            self.ports_thread()
        elif self.menu.get() == "ASN":
            self.asn_thread()
        elif self.menu.get() == "Headers":
            self.get_headers()
        elif self.menu.get() == "JavaScript":
            self.javascript_thread()
        elif self.menu.get() == "Links":
            self.links_thread()
        elif self.menu.get() == "Whois":
            self.whois_thread()
        elif self.menu.get() == "Shodan":
            self.shodan_thread()

    def is_valid_domain(self, domain):
        """
        Validate if the input is a valid domain name.
        Returns True if valid, False otherwise.
        """
        # First clean the domain
        domain = domain.strip()
        domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
        
        # Domain validation regex pattern
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        
        try:
            # Check if the domain matches the pattern
            if not re.match(pattern, domain):
                return False
            
            # Try to resolve the domain
            socket.gethostbyname(domain)
            return True
        except socket.gaierror:
            return False
        
    def shodan(self):
        try:   
            domain = self.entry.get()
            if not domain:
                self.progress_label.configure(text="Please enter a domain or IP")
                return

            # Validate domain first
            #if not self.is_valid_domain(domain):
            #    messagebox.showerror("Error", "Please enter a valid domain name")
            #    self.progress_bar.stop()
            #    self.progress_label.configure(text="Waiting for input...")
            #    self.button.configure(state=ctk.NORMAL)
            #    self.clear_button.configure(state=ctk.NORMAL)
            #    return
                
            # Clear existing entries
            for item in self.shodan_tree.get_children():
                self.shodan_tree.delete(item)
                
            self.progress_label.configure(text="Querying Shodan...")
            self.progress_bar.start()
            
            # Get host information
            info = host_info(domain)
            
            # Insert the information into the tree
            self.shodan_tree.insert("", "end", values=(
                info.get('ip', 'N/A'),
                info.get('org', 'N/A'),
                info.get('ports', 'N/A')
            ))
            
            self.progress_bar.stop()
            self.progress_label.configure(text="Shodan query completed")
            
        except Exception as e:
            self.progress_bar.stop()
            self.progress_label.configure(text=f"Error: {str(e)}")
            print(f"Error in Shodan scan: {e}")


    def process_link(self, link):
        """Process individual link and return formatted result"""
        try:
            href = link.get('href')
            if href.startswith('//'):
                href = f'https:{href}'
            elif href.startswith('/'):
                base_domain = self.entry.get().replace('https://', '').replace('http://', '')
                href = f'https://{base_domain}{href}'
            elif not href.startswith(('http://', 'https://')):
                base_domain = self.entry.get().replace('https://', '').replace('http://', '')
                href = f'https://{base_domain}/{href}'
            return href
        except Exception as e:
            print(f"Error processing link: {e}")
            return None
        
    def process_whois_data(self, key, value):
        """Process individual whois data entries with better formatting"""
        try:
            # Handle lists
            if isinstance(value, list):
                # Join list items with newlines, handle nested structures
                formatted_items = []
                for item in value:
                    if isinstance(item, (dict, list)):
                        formatted_items.append(self.format_complex_value(item))
                    else:
                        formatted_items.append(str(item))
                value = "\n".join(formatted_items)
            
            # Handle dictionaries
            elif isinstance(value, dict):
                value = self.format_complex_value(value)
            
            # Handle dates
            elif "datetime.datetime" in str(type(value)):
                value = value.strftime("%Y-%m-%d %H:%M:%S")
            
            # Handle all other types
            else:
                value = str(value)
            
            return key, value

        except Exception as e:
            print(f"Error processing whois data {key}: {e}")
            return key, "Error processing"

    def format_complex_value(self, value):
        """Format complex data structures (dicts/nested) into readable string"""
        if isinstance(value, dict):
            formatted_items = []
            for k, v in value.items():
                if isinstance(v, (dict, list)):
                    v = self.format_complex_value(v)
                formatted_items.append(f"{k}: {v}")
            return "\n".join(formatted_items)
        
        elif isinstance(value, list):
            for item in value:
                return ",".join(map(str, item))
        
        return str(value)

    def whois(self):
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            
            # Clear existing entries
            for item in self.whois_tree.get_children():
                self.whois_tree.delete(item)
                
            self.progress_bar.start()
            self.progress_label.configure(text="Getting WHOIS information...")

            if not domain:
                messagebox.showerror("Error", "Please enter a domain")
                return
            
            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            try:
                self.start_scan()
                # Clean domain
                domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
                
                # Get both WHOIS and RDAP information
                host = socket.gethostbyname(domain)
                
                # Get domain WHOIS
                w = whois.whois(domain)
                whois_data = w.copy()
                
                # Get RDAP data
                obj = IPWhois(host)
                rdap_results = obj.lookup_rdap(depth=1)
                
                # Combine both results
                combined_data = {**whois_data, **rdap_results}
                
                # Filter out None values and process data concurrently
                filtered_data = {k: v for k, v in combined_data.items() if v is not None}
                total_items = len(filtered_data)
                processed = 0

                self.progress_label.configure(text=f"Processing 0/{total_items} WHOIS entries...")

                max_threads = int(self.thread_entry.get())
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_data = {
                        executor.submit(self.process_whois_data, key, value): (key, value)
                        for key, value in filtered_data.items()
                    }

                    for future in as_completed(future_to_data):
                        if not self.is_scanning:
                            executor.shutdown(wait=False)
                            break
                            
                        processed += 1
                        self.progress_label.configure(
                            text=f"Processing {processed}/{total_items} WHOIS entries..."
                        )
                        
                        try:
                            key, value = future.result()
                            if key and value:
                                self.whois_tree.insert("", "end", values=(key, value))
                        except Exception as e:
                            print(f"Error processing future: {e}")

                self.save_scan_results("whois", None)
                self.progress_bar.stop()
                self.progress_label.configure(text=f"Done! Found {len(self.whois_tree.get_children())} WHOIS entries")

            except Exception as e:
                self.progress_bar.stop()
                self.progress_label.configure(text=f"Error: {str(e)}")
                messagebox.showerror("Error", str(e))

        finally:
            self.is_scanning = False
            self.stop_button.configure(state=ctk.DISABLED)
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)


    def get_links(self):
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            for item in self.links_tree.get_children():
                self.links_tree.delete(item)
            self.progress_bar.start()
            self.progress_label.configure(text="Getting links...")

            if self.entry.get() == "":
                messagebox.showerror("Error", "Please enter a host")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)

            if "https://" not in domain:
                domain = f"https://{domain}"


            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            try:
                self.start_scan()
                s = requests.Session()
                proxy = self.proxy_entry.get()
                user_agent = self.ua_entry.get()
                if user_agent:
                    s.headers["User-Agent"] = user_agent
                if proxy:
                    s.proxies = {"http": proxy, "https": proxy}
                    r = s.get(domain, verify=False, proxies=s.proxies)
                elif user_agent:
                    r = s.get(domain, verify=False, headers={"User-Agent": user_agent})
                elif user_agent and proxy:
                    r = s.get(domain, verify=False, headers={"User-Agent": user_agent}, proxies={"http": proxy, "https": proxy})
                else:
                    r = s.get(domain, verify=False)

                soup = BeautifulSoup(r.content, "html.parser")
                links = soup.find_all('a', href=True)

                total_links = len(links)
                processed = 0
                self.progress_label.configure(text=f"Processing 0/{total_links} links...")

                max_threads = int(self.thread_entry.get()) 
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_link = {
                        executor.submit(self.process_link, link): link 
                        for link in links
                    }

                    for future in as_completed(future_to_link):
                        if not self.is_scanning:
                            executor.shutdown(wait=False)
                            break

                        processed += 1
                        self.progress_label.configure(text=f"Processing {processed}/{total_links} links...")
                        
                        result = future.result()
                        print(result)
                        if result:
                            self.links_tree.insert("", "end", values=(result,))

                self.save_scan_results("links", None)
                self.progress_bar.stop()
                self.progress_label.configure(text=f"Done! Found {len(self.links_tree.get_children())} links")

            except Exception as e:
                self.progress_bar.stop()
                print(f"{e}")
                #self.progress_label.configure(text=f"Error: {str(e)}")

        finally:
            self.is_scanning = False
            self.stop_button.configure(state=ctk.DISABLED)
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)



    def get_javascript_files(self):
        """Retrieve JavaScript files from a domain."""
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            for item in self.javascript_tree.get_children():
                self.javascript_tree.delete(item)
            self.progress_bar.start()
            self.progress_label.configure(text="Getting JavaScript files...")

            # Clean up domain input
            if "https://" in domain:
                domain = domain.replace("https://", "")
            if "https://www." in domain:
                domain = domain.replace("https://www.", "")
            if "http://" in domain:
                domain = domain.replace("http://", "")
            if "http://www." in domain:
                domain = domain.replace("http://www.", "")
            if domain == "":
                messagebox.showerror("Error", "Please enter a domain")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return
            
            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            # Fetch the main page
            url = f"https://{domain}"
            s = requests.Session()
            proxy = self.proxy_entry.get()
            s.proxies = {"http": proxy, "https": proxy}
            if proxy:
                response = s.get(url, verify=False, proxies=s.proxies)
            else:
                response = s.get(url, verify=False)
            soup = BeautifulSoup(response.content, "html.parser")

            # Find all script tags
            scripts = [script.get("src") for script in soup.find_all("script") if script.get("src")]
            js_urls = re.findall(r'url\([\'"]?(.*?\.js)[\'"]?\)', response.text)
            for urls in js_urls:
                full_domain = urljoin(domain, urls)
                scripts.append(full_domain)
                print(full_domain)

            # Update progress label with total count
            total_scripts = len(scripts)
            processed = 0
            self.progress_label.configure(text=f"Processing 0/{total_scripts} JavaScript files...")

            # Download JavaScript files concurrently
            try:
                self.start_scan()
                max_threads = int(self.thread_entry.get())
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    future_to_script = {
                        executor.submit(self.download_script, url, script): script
                        for script in scripts
                    }

                    for future in as_completed(future_to_script):
                        if not self.is_scanning:
                            executor.shutdown(wait=False)
                            break
                        script = future_to_script[future]
                        try:
                            status = future.result()
                            self.javascript_tree.insert("", "end", values=(script, status))
                            processed += 1
                            self.progress_label.configure(
                                text=f"Processing {processed}/{total_scripts} JavaScript files..."
                            )
                        except Exception as e:
                            print(f"Error downloading {script}: {e}")
                
                self.save_scan_results("javascript", None)
                self.progress_bar.stop()
                self.progress_label.configure(
                    text=f"Done! Processed {processed} JavaScript files"
                )
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
            finally:
                self.is_scanning = False
                self.stop_button.configure(state=ctk.DISABLED)
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)



        except Exception as e:
            self.progress_bar.stop()
            self.progress_label.configure(text="Error")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)
            print(f"Main error: {e}")

    def download_script(self, base_url, script_url):
        """Download a JavaScript file and return its status."""
        try:
            if not script_url.startswith("http"):
                script_url = f"{base_url}/{script_url.lstrip('/')}"
            s = requests.Session()
            proxy = self.proxy_entry.get()
            s.proxies = {"http": proxy, "https": proxy}
            if proxy:
                response = requests.get(script_url, verify=False, proxies=s.proxies)
            else:
                response = requests.get(script_url, verify=False)
            if response.status_code == 200:
                return response.status_code
            else:
                return f"{response.status_code}"
        except Exception as e:
            return f"Error: {str(e)}"


    def get_asn_info(self):
        """Get ASN information for a domain"""
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            self.progress_bar.start()
            self.progress_label.configure(text="Getting ASN info...")

            if self.entry.get() == "":
                messagebox.showerror("Error", "Please enter a host")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)

            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            # Get IP address from domain
            ip = socket.gethostbyname(domain)
            
            # Get ASN info
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            # Extract relevant ASN information
            asn_info = {
                'ASN': results.get('asn', 'N/A'),
                'ASN Description': results.get('asn_description', 'N/A'),
                'Organization': results.get('network', {}).get('name', 'N/A'),
                'Country': results.get('asn_country_code', 'N/A')
            }

            # Clear existing items
            for item in self.asn_tree.get_children():
                self.asn_tree.delete(item)

            # Add ASN info to tree
            for prop, value in asn_info.items():
                self.asn_tree.insert("", "end", values=(prop, value))
            
            self.save_scan_results("asn", None)
            self.progress_bar.stop()
            self.progress_label.configure(text="ASN info retrieved successfully!")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)

        except Exception as e:
            self.progress_bar.stop()
            self.progress_label.configure(text=f"Error: {str(e)}")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)

    def scan_port(self, host, port):
        """Scan a single port and identify its service."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    return port, service
        except Exception as e:
            print(f"Error scanning port {port}: {e}")
        return None

    def scan_ports(self):
            """Scan ports and update both ports and services trees."""
            host = self.entry.get()
            host = socket.gethostbyname(host)

            if self.entry.get() == "":
               messagebox.showerror("Error", "Please enter a host")
               self.progress_bar.stop()
               self.progress_label.configure(text="Waiting for input...")
               self.button.configure(state=ctk.NORMAL)
               self.clear_button.configure(state=ctk.NORMAL)
               return
            elif self.startport_entry.get() == "" or self.endport_entry.get() == "":
                messagebox.showerror("Error", "Please enter a start and end port")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return
            
            # Clear existing entries
            for tree in [self.ports_tree, self.services_tree]:
                for item in tree.get_children():
                    tree.delete(item)
                    
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            self.progress_bar.start()

            try:    
                total_ports = int(self.endport_entry.get())
                start_port = int(self.startport_entry.get())
            except ValueError:
                messagebox.showerror("Error", "It needs to be an integer")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            if total_ports == "" or start_port == "":
                messagebox.WARNING("Don't leave the port entries blank")

            scanned = 0
            open_ports = []

            try:
                self.start_scan()

                max_threads = int(self.thread_entry.get())
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    futures = {executor.submit(self.scan_port, host, port): port for port in range(start_port, total_ports)}
                    for future in as_completed(futures):
                        if not self.is_scanning:
                            executor.shutdown(wait=False)
                            break
                        scanned += 1
                        self.progress_label.configure(text=f"Scanning ports... ({scanned}/{total_ports-1})")
                        
                        result = future.result()
                        if result:
                            port, service = result
                            open_ports.append(port)
                            self.ports_tree.insert("", "end", values=(port,))
                            self.services_tree.insert("", "end", values=(f"{service}"))
                
                self.save_scan_results("ports", None)
                self.progress_bar.stop()
                self.progress_label.configure(text=f"Done! Found {len(open_ports)} open ports")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
            finally:
                self.is_scanning = False
                self.stop_button.configure(state=ctk.DISABLED)
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)



    def get_headers(self):
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            self.progress_bar.start()
            self.progress_label.configure(text="Getting headers...")
            if "https://" in domain:
                domain = domain.replace("https://", "")
            if "https://www." in domain:
                domain = domain.replace("https://www.", "")
            if "http://" in domain:
                domain = domain.replace("http://", "")
            if "http://www." in domain:
                domain = domain.replace("http://www.", "")
            if domain == "":
                messagebox.showerror("Error", "Please enter a domain")

            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            s = requests.Session()
            proxy = self.proxy_entry.get()
            s.proxies = {"http": proxy, "https": proxy}
            if proxy:
                r = s.get(f"https://{domain}", verify=False, proxies=s.proxies)
            else:
                r = s.get(f"https://{domain}", verify=False)
            for header, value in r.headers.items():
                self.headers_tree.insert("", "end", values=(header, value))
            self.save_scan_results("headers", None)
            self.progress_bar.stop()
            self.progress_label.configure(text="Done!")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)
        except Exception as e:
            self.progress_bar.stop()
            self.progress_label.configure(text="Error")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)


    def process_subdomain(self, subdomain):
        """Helper function to process individual subdomains"""
        try:
            s = requests.Session()
            proxy = self.proxy_entry.get()
            s.proxies = {"http": proxy, "https": proxy}
            if proxy:
                r = s.get(f"https://{subdomain}", verify=False, timeout=5, proxies=s.proxies)
            else:
                r = s.get(f"https://{subdomain}", verify=False, timeout=5)
            ip = socket.gethostbyname(subdomain)
            return (subdomain, r.status_code, ip, r.headers.get("Server"))
        except Exception as e:
            print(f"Error processing {subdomain}: {e}")
            return (subdomain, "Error", str(e)[:50], "N/A")

    def get_subdomains(self):
        try:
            domain = self.entry.get()
            self.button.configure(state=ctk.DISABLED)
            self.clear_button.configure(state=ctk.DISABLED)
            for item in self.subdomain_tree.get_children():
                self.subdomain_tree.delete(item)
            self.progress_bar.start()
            self.progress_label.configure(text="Getting subdomains...")

            if "https://" in domain:
                domain = domain.replace("https://", "")
            if "https://www." in domain:
                domain = domain.replace("https://www.", "")
            if "http://" in domain:
                domain = domain.replace("http://", "")
            if "http://www." in domain:
                domain = domain.replace("http://www.", "")
            if domain == "":
                messagebox.showerror("Error", "Please enter a domain")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return
            # Validate domain first
            if not self.is_valid_domain(domain):
                messagebox.showerror("Error", "Please enter a valid domain name")
                self.progress_bar.stop()
                self.progress_label.configure(text="Waiting for input...")
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
                return

            # Get subdomains list first
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            spotter_path = os.path.join(current_script_dir, 'scripts', 'spotter.sh')
            certsh_path = os.path.join(current_script_dir, 'scripts', 'certsh.sh')

            cmd = f"{spotter_path} {domain} | uniq | sort"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            spotterout, err = p.communicate()
            spotterout = spotterout.decode()

            cmd = f"{certsh_path} {domain} | uniq | sort"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            certshout, err = p.communicate()
            certshout = certshout.decode()

            cmd = f"subfinder -d {domain} -silent"
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            subdomains = [line.decode().strip() for line in p.stdout if line.decode().strip()]
            subdomains = list(set(subdomains))
            subdomains.extend(spotterout.split("\n"))
            subdomains.extend(certshout.split("\n"))

            # Update progress label with total count
            total_subdomains = len(subdomains)
            processed = 0
            self.progress_label.configure(text=f"Processing 0/{total_subdomains} subdomains...")

            # Process subdomains concurrently
            try:
                self.start_scan()

                max_threads = int(self.thread_entry.get())
                with ThreadPoolExecutor(max_workers=max_threads) as executor:
                    # Submit all tasks
                    future_to_subdomain = {
                        executor.submit(self.process_subdomain, subdomain): subdomain 
                        for subdomain in subdomains
                    }

                    # Process completed tasks as they finish
                    for future in as_completed(future_to_subdomain):
                        if not self.is_scanning:
                            executor.shutdown(wait=False)
                            break
                        try:
                            result = future.result()
                            if "Error" not in result:
                                self.subdomain_tree.insert("", "end", values=result)
                                processed += 1
                                # Update progress
                                self.progress_label.configure(
                                    text=f"Processing {processed}/{total_subdomains} subdomains..."
                                )
                            elif "Error" in result:
                                pass
                        except Exception as e:
                            print(f"Task error: {e}")

                self.progress_bar.stop()
                self.progress_label.configure(
                    text=f"Done! Found {len(self.subdomain_tree.get_children())} subdomains"
                )
                self.save_scan_results("subdomains", None)
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)
    
            finally:
                self.is_scanning = False
                self.stop_button.configure(state=ctk.DISABLED)
                self.button.configure(state=ctk.NORMAL)
                self.clear_button.configure(state=ctk.NORMAL)    

        except Exception as e:
            self.progress_bar.stop()
            self.progress_label.configure(text="Error")
            self.button.configure(state=ctk.NORMAL)
            self.clear_button.configure(state=ctk.NORMAL)
            print(f"Main error: {e}")

    def clear_textbox(self):
        if self.menu.get() == "Subdomain":
            self.subdomain_tree.delete(*self.subdomain_tree.get_children())
        if self.menu.get() == "Port Scan":
            self.ports_tree.delete(*self.ports_tree.get_children())
            self.services_tree.delete(*self.services_tree.get_children())
        if self.menu.get() == "ASN":
            self.asn_tree.delete(*self.asn_tree.get_children())
        self.progress_label.configure(text="Waiting for input...")
        if self.menu.get() == "JavaScript":
            self.javascript_tree.delete(*self.javascript_tree.get_children())
        self.progress_label.configure(text="Waiting for input...")
        if self.menu.get() == "Headers":
            self.headers_tree.delete(*self.headers_tree.get_children())
            self.progress_label.configure(text="Waiting for input...")
        if self.menu.get() == "Links":
            self.links_tree.delete(*self.links_tree.get_children())
            self.progress_label.configure(text="Waiting for input...")
        if self.menu.get() == "Shodan":
            self.shodan_tree.delete(*self.shodan_tree.get_children())
            self.progress_label.configure(text="Waiting for input...")

    def subdomain_thread(self):
        threading.Thread(target=self.get_subdomains).start()
    
    def headers_thread(self):
        threading.Thread(target=self.get_headers).start()

    def ports_thread(self):
        threading.Thread(target=self.scan_ports).start()

    def asn_thread(self):
        threading.Thread(target=self.get_asn_info).start()

    def javascript_thread(self):
        threading.Thread(target=self.get_javascript_files).start()

    def links_thread(self):
        threading.Thread(target=self.get_links).start()

    def whois_thread(self):
        threading.Thread(target=self.whois).start()

    def shodan_thread(self):
        threading.Thread(target=self.shodan).start()

    def save_scan_results(self, scan_type, results):
        """Save scan results to a file if checkbox is checked"""
        if not self.save_results_var.get():
            return
            
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = self.entry.get().replace("https://", "").replace("http://", "").replace("/", "_")
        filename = f"results/{domain}_{scan_type}_{timestamp}.txt"
        
        # Create results directory if it doesn't exist
        os.makedirs("results", exist_ok=True)
        
        try:
            with open(filename, "w") as f:
                if scan_type == "subdomains":
                    for item in self.subdomain_tree.get_children():
                        values = self.subdomain_tree.item(item)["values"]
                        f.write(f"Domain: {values[0]}, Status: {values[1]}, IP: {values[2]}, Server: {values[3]}\n")
                
                elif scan_type == "ports":
                    for item in self.ports_tree.get_children():
                        port = self.ports_tree.item(item)["values"][0]
                        f.write(f"Open Port: {port}\n")
                    
                elif scan_type == "asn":
                    for item in self.asn_tree.get_children():
                        values = self.asn_tree.item(item)["values"]
                        f.write(f"{values[0]}: {values[1]}\n")
                
                elif scan_type == "headers":
                    for item in self.headers_tree.get_children():
                        values = self.headers_tree.item(item)["values"]
                        f.write(f"{values[0]}: {values[1]}\n")
                
                elif scan_type == "javascript":
                    for item in self.javascript_tree.get_children():
                        values = self.javascript_tree.item(item)["values"]
                        f.write(f"File: {values[0]}, Status: {values[1]}\n")
                
                elif scan_type == "links":
                    for item in self.links_tree.get_children():
                        link = self.links_tree.item(item)["values"][0]
                        f.write(f"{link}\n")
                
                elif scan_type == "whois":
                    for item in self.whois_tree.get_children():
                        values = self.whois_tree.item(item)["values"]
                        f.write(f"{values[0]}: {values[1]}\n")
                        
            print(f"Results saved to {filename}")
            
        except Exception as e:
            print(f"Error saving results: {e}")


if __name__ == "__main__":
    reconx = ReconX()
    reconx.window.mainloop()
