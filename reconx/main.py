import customtkinter as ctk
import tkinter as tk
from PIL import Image
import os
import threading
import requests
import socket
import re
import whois
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.subenum import SubdomainEnumerator
from tkinter import messagebox, ttk
import json
import sys
import queue
import time
from googlesearch import search
from github import Github
import urllib.parse
from modules.dorking import DorkScanner
from modules.portscan import PortScanner
from modules.headers import HeaderScanner

class ReconX:
    def __init__(self):
        # Refined Color Palette with Dark Theme
        self.colors = {
            "background": "#121212",      # Deep dark background
            "primary": "#1E88E5",         # Vibrant blue
            "secondary": "#1E1E1E",       # Slightly lighter than background
            "text": "#E0E0E0",            # Soft light grey (not pure white)
            "accent": "#4FC3F7",          # Light blue accent
            "hover": "#2C3E50",           # Dark hover color
            "border": "#2C3E50"           # Dark border color
        }

        # Main Window Setup
        self.window = ctk.CTk()
        self.window.title("ReconX - Reconnaissance Framework")
        self.window.geometry("1100x700")
        self.window.configure(fg_color=self.colors["background"])

        # Custom Styling
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Load icons first
        self.load_icons()

        # Treeview Style
        self.style = ttk.Style()
        self.style.theme_use("default")
        self.style.configure("Treeview", 
            background=self.colors["background"],
            foreground=self.colors["text"],
            fieldbackground=self.colors["background"],
            font=('Arial', 10)
        )
        self.style.map("Treeview", 
            background=[('selected', self.colors["primary"])],
            foreground=[('selected', self.colors["text"])]
        )

        # Setup Main Layout
        self.create_layout()
        self.create_navigation()
        self.create_content_area()
        self.setup_theme()

        # Existing features setup
        self.is_scanning = False
        self.current_scan_type = None

        # Add a status queue for thread communication
        self.status_queue = queue.Queue()
        self.status_update_id = None

    def load_icons(self):
        """Load all icons for use in the application"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(current_dir, "icons/")
        
        self.icons = {
            "start": ctk.CTkImage(Image.open(os.path.join(icon_path, "start.png")), size=(20, 20)),
            "stop": ctk.CTkImage(Image.open(os.path.join(icon_path, "stop.png")), size=(20, 20)),
            "logo": ctk.CTkImage(Image.open(os.path.join(icon_path, "logo.png")), size=(100, 100))
        }

    def create_layout(self):
        # Main container with grid layout
        self.main_container = ctk.CTkFrame(
            self.window, 
            fg_color=self.colors["background"],
            corner_radius=0
        )
        self.main_container.pack(fill="both", expand=True)

        # Grid configuration - simplified and fixed
        self.main_container.grid_columnconfigure(1, weight=1)  # Content area
        self.main_container.grid_columnconfigure(0, weight=0)  # Navigation area
        self.main_container.grid_rowconfigure(0, weight=1)

    def create_navigation(self):
        # Navigation container frame
        self.nav_container = ctk.CTkFrame(
            self.main_container,
            fg_color=self.colors["secondary"],
            corner_radius=0
        )
        self.nav_container.grid(row=0, column=0, sticky="nsew")
        
        # Toggle button at top of nav container
        self.sidebar_toggle_btn = ctk.CTkButton(
            self.nav_container,
            text="☰",
            fg_color="transparent",
            hover_color=self.colors["hover"],
            text_color=self.colors["text"],
            width=30,
            height=30,
            command=self.toggle_sidebar
        )
        self.sidebar_toggle_btn.pack(side="top", padx=5, pady=5)

        # Navigation buttons frame
        self.nav_frame = ctk.CTkFrame(
            self.nav_container,
            fg_color="transparent",
            width=200
        )
        self.nav_frame.pack(fill="both", expand=True)

        # Navigation Buttons
        nav_items = [
            {"name": "Dashboard", "icon": "home.png", "command": self.show_dashboard},
            {"name": "Subdomain", "icon": "domains.png", "command": self.show_subdomain_scan},
            {"name": "Port Scan", "icon": "network.png", "command": self.show_port_scan},
            {"name": "Headers", "icon": "headers.png", "command": self.show_headers_scan},
            {"name": "Dork", "icon": "dork.png", "command": self.show_dork_scan},
            # {"name": "ASN", "icon": "asn.png", "command": self.show_asn_scan},
            # {"name": "JavaScript", "icon": "javascript.png", "command": self.show_js_scan},
            {"name": "Settings", "icon": "settings.png", "command": self.show_settings}
        ]

        for item in nav_items:
            self.create_nav_button(item)

    def create_nav_button(self, item):
        """Navigation button with consistent dark theme styling"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(current_dir, "icons", item["icon"])
        
        try:
            icon = ctk.CTkImage(
                Image.open(icon_path), 
                size=(25, 25)
            )
        except Exception:
            icon = None

        button = ctk.CTkButton(
            self.nav_frame, 
            text=item["name"],
            image=icon,
            fg_color=self.colors["secondary"],
            text_color=self.colors["text"],
            hover_color=self.colors["hover"],
            corner_radius=5,
            anchor="w"
        )
        button.pack(fill="x", padx=5, pady=3)

    def create_content_area(self):
        """Content area with dark theme styling"""
        # Main content frame
        self.content_frame = ctk.CTkFrame(
            self.main_container, 
            fg_color=self.colors["background"],
            corner_radius=0
        )
        self.content_frame.grid(row=0, column=1, sticky="nsew")

        # Input area
        self.input_frame = ctk.CTkFrame(
            self.content_frame, 
            fg_color=self.colors["secondary"],
            border_color=self.colors["border"],
            border_width=1
        )
        self.input_frame.pack(fill="x", padx=10, pady=10)

        # Domain input
        self.domain_entry = ctk.CTkEntry(
            self.input_frame, 
            placeholder_text="Enter domain or IP",
            width=600,
            fg_color=self.colors["background"],
            text_color=self.colors["text"],
            placeholder_text_color=self.colors["text"],
            border_color=self.colors["border"]
        )
        self.domain_entry.pack(side="left", padx=10, pady=10, expand=True, fill="x")

        # Enhanced scan button with icon
        self.scan_button = ctk.CTkButton(
            self.input_frame, 
            text="Start Scan",
            image=self.icons["start"],
            compound="left",
            fg_color=self.colors["primary"],
            hover_color=self.colors["accent"],
            text_color=self.colors["text"]
        )
        self.scan_button.pack(side="right", padx=10, pady=10)

        # Add stop button (initially disabled)
        self.stop_button = ctk.CTkButton(
            self.input_frame,
            text="Stop",
            image=self.icons["stop"],
            compound="left",
            fg_color=self.colors["secondary"],
            hover_color="#FF4444",
            text_color=self.colors["text"],
            state="disabled",
            command=self.stop_scan
        )
        self.stop_button.pack(side="right", padx=5, pady=10)

        # Enhanced status bar with pulsing animation
        self.status_frame = ctk.CTkFrame(
            self.content_frame,
            fg_color=self.colors["secondary"],
            height=30
        )
        self.status_frame.pack(fill="x", side="bottom", padx=10, pady=5)
        self.status_frame.pack_propagate(False)

        self.status_indicator = ctk.CTkLabel(
            self.status_frame,
            text="●",
            text_color=self.colors["primary"],
            width=20
        )
        self.status_indicator.pack(side="left", padx=5)

        self.status_bar = ctk.CTkLabel(
            self.status_frame,
            text="Ready to scan",
            text_color=self.colors["text"],
            anchor="w"
        )
        self.status_bar.pack(side="left", fill="x", expand=True, padx=5)

        # Results area
        self.results_frame = ctk.CTkFrame(
            self.content_frame, 
            fg_color=self.colors["background"],
            border_color=self.colors["border"],
            border_width=1
        )
        self.results_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(
            self.content_frame, 
            fg_color=self.colors["secondary"],
            progress_color=self.colors["primary"]
        )
        self.progress_bar.pack(fill="x", side="bottom", padx=10, pady=5)
        self.progress_bar.set(0)

    def setup_theme(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

    def show_dashboard(self):
        """Enhanced dashboard with system information"""
        # Clear previous content
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Dashboard layout
        dashboard_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        dashboard_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # Welcome section
        welcome_label = ctk.CTkLabel(
            dashboard_frame, 
            text="Welcome to ReconX",
            font=("Arial", 24, "bold"),
            text_color=self.colors["text"]
        )
        welcome_label.pack(pady=10)

        # Quick stats or system info
        info_frame = ctk.CTkFrame(dashboard_frame, fg_color=self.colors["secondary"])
        info_frame.pack(fill="x", pady=10)

        # Example system info (you can expand this)
        info_items = [
            f"Python Version: {sys.version.split()[0]}",
            f"Available Scan Modules: 3",
            "Last Scan: Not available"
        ]

        for item in info_items:
            info_label = ctk.CTkLabel(
                info_frame, 
                text=item, 
                text_color=self.colors["text"],
                anchor="w"
            )
            info_label.pack(fill="x", padx=10, pady=5)

    def create_results_treeview(self):
        """Create a standard treeview for results"""
        # Clear existing widgets
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Create Treeview
        self.results_tree = ttk.Treeview(
            self.results_frame, 
            style="Treeview"
        )
        self.results_tree.pack(fill="both", expand=True, padx=10, pady=10)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(
            self.results_frame, 
            orient="vertical", 
            command=self.results_tree.yview
        )
        scrollbar.pack(side="right", fill="y")
        self.results_tree.configure(yscrollcommand=scrollbar.set)

    def show_subdomain_scan(self):
        """Prepare UI for subdomain scanning"""
        self.create_results_treeview()
        
        # Configure treeview columns
        self.results_tree['columns'] = ("Domain", "Status Code", "IP", "Server")
        self.results_tree.heading("Domain", text="Domain")
        self.results_tree.heading("Status Code", text="Status Code")
        self.results_tree.heading("IP", text="IP")
        self.results_tree.heading("Server", text="Server")

        # Update scan button
        self.scan_button.configure(command=self.start_subdomain_scan)
        self.current_scan_type = "subdomain"

    def start_subdomain_scan(self):
        """Start subdomain enumeration with status monitoring"""
        domain = self.domain_entry.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start status monitoring
        self.start_status_monitoring()

        # Start scanning in a thread
        threading.Thread(target=self._run_subdomain_scan, args=(domain,), daemon=True).start()

    def _run_subdomain_scan(self, domain):
        """Enhanced subdomain scanning with detailed progress"""
        try:
            # Initial status update
            self.status_queue.put({'type': 'message', 'text': f'Starting subdomain scan for {domain}'})
            self.status_queue.put({'type': 'progress', 'value': 0.1})

            enumerator = SubdomainEnumerator(domain)
            subdomains = list(enumerator.enumerate())
            total_subdomains = len(subdomains)

            # Update progress and status
            self.status_queue.put({'type': 'message', 'text': f'Found {total_subdomains} potential subdomains'})
            self.status_queue.put({'type': 'progress', 'value': 0.3})

            # Process subdomains
            processed_count = 0
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_subdomain = {
                    executor.submit(self._process_subdomain, subdomain): subdomain 
                    for subdomain in subdomains
                }
                
                for future in as_completed(future_to_subdomain):
                    result = future.result()
                    processed_count += 1
                    
                    # Update progress
                    progress = 0.3 + (processed_count / total_subdomains * 0.6)
                    self.status_queue.put({
                        'type': 'message', 
                        'text': f'Processed {processed_count}/{total_subdomains} subdomains'
                    })
                    self.status_queue.put({'type': 'progress', 'value': progress})

                    if result:
                        self.window.after(0, self._update_subdomain_tree, result)

            # Scan complete
            self.status_queue.put({'type': 'complete'})
            self.status_queue.put({'type': 'message', 'text': f'Subdomain scan completed. Found active subdomains.'})

        except Exception as e:
            self.status_queue.put({'type': 'message', 'text': f'Scan Error: {str(e)}'})
            messagebox.showerror("Scan Error", str(e))

    def _process_subdomain(self, subdomain):
        """Process individual subdomain"""
        try:
            response = requests.get(f"https://{subdomain}", timeout=5)
            ip = socket.gethostbyname(subdomain)
            return (subdomain, response.status_code, ip, response.headers.get("Server", "N/A"))
        except Exception:
            return None

    def _update_subdomain_tree(self, result):
        """Update treeview with subdomain result"""
        self.results_tree.insert("", "end", values=result)

    def show_port_scan(self):
        """Prepare UI for port scanning"""
        self.create_results_treeview()
        
        # Configure treeview columns
        self.results_tree['columns'] = ("Ports", "Services")
        self.results_tree.heading("Ports", text="Ports")
        self.results_tree.heading("Services", text="Services")

        # Update scan button
        self.scan_button.configure(command=self.start_port_scan)
        self.current_scan_type = "port"

    def start_port_scan(self):
        """Start port scanning"""
        host = self.domain_entry.get()
        if not host:
            messagebox.showerror("Error", "Please enter a host")
            return

        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start status monitoring
        self.start_status_monitoring()
        
        # Initialize scanner
        scanner = PortScanner(self.status_queue)
        
        def run_scan():
            try:
                results = scanner.scan(host)
                for result in results:
                    self.window.after(0, self._update_port_tree, result)
            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            finally:
                self.window.after(0, self.stop_scan)
        
        # Start scan in thread
        threading.Thread(target=run_scan, daemon=True).start()

    def _update_port_tree(self, result):
        """Update treeview with port result"""
        self.results_tree.insert("", "end", values=result)

    def show_headers_scan(self):
        """Prepare UI for headers scanning"""
        self.create_results_treeview()
        
        # Configure treeview columns
        self.results_tree['columns'] = ("Header", "Value")
        self.results_tree.heading("Header", text="Header")
        self.results_tree.heading("Value", text="Value")

        # Update scan button
        self.scan_button.configure(command=self.start_headers_scan)
        self.current_scan_type = "headers"

    def start_headers_scan(self):
        """Start headers scanning"""
        domain = self.domain_entry.get()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return

        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start status monitoring
        self.start_status_monitoring()
        
        # Initialize scanner
        scanner = HeaderScanner(self.status_queue)
        
        def run_scan():
            try:
                results = scanner.scan(domain)
                for result in results:
                    self.window.after(0, self._update_headers_tree, result)
            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            finally:
                self.window.after(0, self.stop_scan)
        
        # Start scan in thread
        threading.Thread(target=run_scan, daemon=True).start()

    def _update_headers_tree(self, result):
        """Update treeview with headers result"""
        self.results_tree.insert("", "end", values=result)

    # Add similar methods for ASN, JS, and other scans...

    def show_settings(self):
        """Show settings panel"""
        # Clear previous content
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Settings label
        settings_label = ctk.CTkLabel(
            self.results_frame, 
            text="Settings",
            font=("Arial", 24, "bold"),
            text_color=self.colors["text"]
        )
        settings_label.pack(pady=20)

    def update_status(self):
        """Enhanced status updates with visual feedback"""
        try:
            while not self.status_queue.empty():
                status = self.status_queue.get_nowait()
                
                if status['type'] == 'progress':
                    self.progress_bar.set(status['value'])
                    
                elif status['type'] == 'message':
                    if 'error' in status.get('text', '').lower():
                        self.status_indicator.configure(text_color="#FF4444")
                        self.status_bar.configure(text_color="#FF4444")
                    elif 'complete' in status.get('text', '').lower():
                        self.status_indicator.configure(text_color="#4CAF50")
                        self.status_bar.configure(text_color="#4CAF50")
                    else:
                        self.status_indicator.configure(text_color=self.colors["primary"])
                        self.status_bar.configure(text_color=self.colors["text"])
                    
                    self.status_bar.configure(text=status['text'])
                    
                elif status['type'] == 'complete':
                    self.progress_bar.set(1)
                    self.stop_scan()
                    threading.Timer(1, self.reset_progress).start()
                    
        except queue.Empty:
            pass

        if self.is_scanning:
            self.status_update_id = self.window.after(100, self.update_status)

    def stop_scan(self):
        """Stop scanning with visual feedback"""
        self.is_scanning = False
        self.stop_button.configure(state="disabled")
        self.scan_button.configure(state="normal")
        self.status_indicator.configure(text_color=self.colors["text"])
        self.status_bar.configure(
            text="Scan stopped",
            text_color=self.colors["text"]
        )

    def reset_progress(self):
        """Enhanced progress reset with visual feedback"""
        self.progress_bar.set(0)
        self.is_scanning = False
        self.stop_button.configure(state="disabled")
        self.scan_button.configure(state="normal")
        self.status_indicator.configure(text_color="#4CAF50")
        self.status_bar.configure(
            text="Scan completed successfully",
            text_color="#4CAF50"
        )
        
        # Reset after 3 seconds
        self.window.after(3000, lambda: (
            self.status_indicator.configure(text_color=self.colors["text"]),
            self.status_bar.configure(
                text="Ready for next scan",
                text_color=self.colors["text"]
            )
        ))
        
        if self.status_update_id:
            self.window.after_cancel(self.status_update_id)

    def start_status_monitoring(self):
        """Enhanced status monitoring with visual feedback"""
        if self.status_update_id:
            self.window.after_cancel(self.status_update_id)
        
        # Start pulsing animation
        self.pulse_animation()
        
        # Enable stop button, update scan button
        self.stop_button.configure(state="normal")
        self.scan_button.configure(state="disabled")
        
        # Start monitoring
        self.status_update_id = self.window.after(100, self.update_status)

    def pulse_animation(self):
        """Create pulsing animation for status indicator"""
        if not hasattr(self, 'pulse_colors'):
            self.pulse_colors = [
                self.colors["primary"],
                self.colors["accent"],
                "#2196F3",
                "#64B5F6",
                "#90CAF9"
            ]
            self.pulse_index = 0

        if self.is_scanning:
            self.status_indicator.configure(text_color=self.pulse_colors[self.pulse_index])
            self.pulse_index = (self.pulse_index + 1) % len(self.pulse_colors)
            self.window.after(500, self.pulse_animation)

    def toggle_sidebar(self):
        """Toggle sidebar visibility"""
        current_width = self.nav_container.winfo_width()
        
        if current_width > 50:  # If sidebar is expanded
            # Collapse
            self.nav_container.configure(width=50)
            self.nav_frame.pack_forget()  # Hide navigation buttons
            self.sidebar_toggle_btn.configure(text="☰")
        else:
            # Expand
            self.nav_container.configure(width=200)
            self.nav_frame.pack(fill="both", expand=True)  # Show navigation buttons
            self.sidebar_toggle_btn.configure(text="✕")

    def show_dork_scan(self):
        """Prepare UI for dorking"""
        # Clear existing widgets
        for widget in self.results_frame.winfo_children():
            widget.destroy()

        # Create dork type selection frame
        dork_type_frame = ctk.CTkFrame(
            self.results_frame,
            fg_color=self.colors["secondary"]
        )
        dork_type_frame.pack(fill="x", padx=10, pady=5)

        # Dork type selector
        self.dork_type = ctk.CTkSegmentedButton(
            dork_type_frame,
            values=["Google Dork", "GitHub Dork"],
            command=self.on_dork_type_change
        )
        self.dork_type.pack(padx=10, pady=5)
        self.dork_type.set("Google Dork")

        # GitHub API Key frame (initially hidden)
        self.github_api_frame = ctk.CTkFrame(
            self.results_frame,
            fg_color=self.colors["secondary"]
        )
        
        self.github_api_entry = ctk.CTkEntry(
            self.github_api_frame,
            placeholder_text="Enter GitHub API Key",
            width=300
        )
        self.github_api_entry.pack(padx=10, pady=5)

        # Create Treeview for results
        self.create_results_treeview()
        self.results_tree['columns'] = ("Title", "URL", "Description")
        self.results_tree.heading("Title", text="Title")
        self.results_tree.heading("URL", text="URL")
        self.results_tree.heading("Description", text="Description")
        
        # Column widths
        self.results_tree.column("Title", width=200)
        self.results_tree.column("URL", width=300)
        self.results_tree.column("Description", width=400)

        # Update scan button
        self.scan_button.configure(command=self.start_dork_scan)
        self.current_scan_type = "dork"

    def on_dork_type_change(self, value):
        """Handle dork type change"""
        if value == "GitHub Dork":
            self.github_api_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.github_api_frame.pack_forget()

    def start_dork_scan(self):
        """Start dorking scan"""
        query = self.domain_entry.get()
        if not query:
            messagebox.showerror("Error", "Please enter a search query")
            return

        # Clear existing results
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

        # Start status monitoring
        self.start_status_monitoring()
        
        # Initialize scanner
        scanner = DorkScanner(self.status_queue)
        
        # Start appropriate scan based on type
        dork_type = self.dork_type.get()
        
        def run_scan():
            try:
                if dork_type == "GitHub Dork":
                    api_key = self.github_api_entry.get()
                    if not api_key:
                        messagebox.showerror("Error", "GitHub API key is required")
                        return
                    results = scanner.github_dork(query, api_key)
                else:
                    results = scanner.google_dork(query)
                
                # Update results in UI
                for result in results:
                    self.window.after(0, self._update_dork_tree, result)
                    
            except Exception as e:
                self.window.after(0, lambda: messagebox.showerror("Scan Error", str(e)))
            
            finally:
                self.window.after(0, self.stop_scan)
        
        # Start scan in thread
        threading.Thread(target=run_scan, daemon=True).start()

    def _update_dork_tree(self, result):
        """Update treeview with dork result"""
        self.results_tree.insert("", "end", values=result)

def main():
    app = ReconX()
    app.window.mainloop()

if __name__ == "__main__":
    main()
