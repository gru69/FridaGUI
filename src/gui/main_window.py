from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                           QPushButton, QStackedWidget, QLabel, QListWidget, QTableWidget, QGroupBox, QCheckBox, QSpinBox, QMessageBox, QScrollArea, QGridLayout, QLineEdit, QTextEdit, QFrame, QDialog, QFileDialog)
from PyQt5.QtCore import Qt, QSize
import qtawesome as qta
from .widgets.device_panel import DevicePanel
from .widgets.process_panel import ProcessPanel
from .widgets.script_editor import ScriptEditorPanel
from .widgets.output_panel import OutputPanel
from .widgets.codeshare_browser import CodeShareBrowser
from .widgets.app_launcher import AppLauncher
from .widgets.process_monitor import ProcessMonitor
from .widgets.injection_panel import InjectionPanel
from .widgets.device_selector import DeviceSelector
from .widgets.history_page import HistoryPage
from core.history_manager import HistoryManager
from core.android_helper import AndroidHelper
import frida
import subprocess
import os
import json
import requests

class FridaInjectorMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Oliver Stankiewicz's | Frida Script Manager")
        self.setMinimumSize(1400, 800)
        self.history_manager = HistoryManager()
        self.favorites = []  # Initialize favorites list
        self.load_favorites()  # Load favorites on startup
        self.setup_ui()
        
        # Connect codeshare and favorites browsers
        self.codeshare_browser.favorites_updated.connect(self.refresh_favorites)
        
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main horizontal layout
        layout = QHBoxLayout(central_widget)
        
        # Left sidebar for navigation
        sidebar = self.create_sidebar()
        layout.addWidget(sidebar)
        
        # Stacked widget for main content
        self.stack = QStackedWidget()
        layout.addWidget(self.stack)
        
        # Set layout ratio (1:4)
        layout.setStretch(0, 1)
        layout.setStretch(1, 4)
        
        # Initialize pages
        self.init_pages()
        
    def create_sidebar(self):
        sidebar = QWidget()
        sidebar.setObjectName("sidebar")
        sidebar.setStyleSheet("""
            QWidget#sidebar {
                background-color: #2f3136;
                border-right: 1px solid #202225;
                min-width: 180px;
                max-width: 180px;
            }
            QPushButton {
                text-align: left;
                padding: 6px 8px;
                border: none;
                border-radius: 4px;
                margin: 1px 4px;
                min-height: 32px;
                max-height: 32px;
                font-size: 13px;
            }
            QPushButton:hover {
                background-color: #36393f;
            }
            QPushButton:checked {
                background-color: #404249;
            }
        """)
        
        layout = QVBoxLayout(sidebar)
        layout.setSpacing(1)
        layout.setContentsMargins(0, 5, 0, 5)
        
        # Add navigation buttons
        self.nav_buttons = {}
        
        nav_items = [
            ("home", "Home", "fa5s.home"),
            ("inject", "Script Injection", "fa5s.syringe"),
            ("codeshare", "CodeShare", "fa5s.cloud-download-alt"),
            ("favorites", "Favorites", "fa5s.star"),
            ("history", "History", "fa5s.history"),
            ("monitor", "Process Monitor", "fa5s.desktop"),
            ("settings", "Settings", "fa5s.cog")
        ]
        
        for id_, text, icon in nav_items:
            btn = QPushButton(qta.icon(icon, color='#b9bbbe'), f" {text}")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, x=id_: self.switch_page(x))
            # Set icon size
            btn.setIconSize(QSize(14, 14))
            self.nav_buttons[id_] = btn
            layout.addWidget(btn)
            
        layout.addStretch()
        
        # Add status indicator at bottom
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(8, 4, 8, 4)
        self.status_icon = QLabel()
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(8, 8))
        self.status_text = QLabel("Ready")
        self.status_text.setStyleSheet("color: #b9bbbe; font-size: 12px;")
        status_layout.addWidget(self.status_icon)
        status_layout.addWidget(self.status_text)
        layout.addLayout(status_layout)
        
        return sidebar
        
    def init_pages(self):
        # Create pages
        self.pages = {
            'home': self.create_home_page(),
            'inject': self.create_injection_page(),
            'codeshare': self.create_codeshare_page(),
            'favorites': self.create_favorites_page(),
            'history': self.create_history_page(),
            'monitor': self.create_monitor_page(),
            'settings': self.create_settings_page()
        }
        
        # Add pages to stack
        for page in self.pages.values():
            self.stack.addWidget(page)
            
        # Set initial page
        self.switch_page('home')
        
    def switch_page(self, page_id):
        # Update button states
        for btn in self.nav_buttons.values():
            btn.setChecked(False)
        self.nav_buttons[page_id].setChecked(True)
        
        # Switch to page
        self.stack.setCurrentWidget(self.pages[page_id])
        
    def create_home_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setSpacing(20)
        
        # Welcome header
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 10px;
                padding: 20px;
            }
            QLabel {
                color: white;
            }
        """)
        header_layout = QVBoxLayout(header)
        
        title = QLabel("Welcome to Frida Script Manager")
        title.setStyleSheet("font-size: 24px; font-weight: bold;")
        
        subtitle = QLabel("A powerful GUI tool for Frida script management and injection")
        subtitle.setStyleSheet("font-size: 16px; color: #b9bbbe;")
        
        author = QLabel("Created by Oliver Stankiewicz")
        author.setStyleSheet("font-size: 14px; color: #7289da;")
        
        header_layout.addWidget(title)
        header_layout.addWidget(subtitle)
        header_layout.addWidget(author)
        
        # Quick actions section
        actions = QFrame()
        actions.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 10px;
                padding: 20px;
            }
            QLabel {
                color: white;
            }
            QPushButton {
                background-color: #7289da;
                border-radius: 5px;
                padding: 10px;
                color: white;
                text-align: left;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #677bc4;
            }
        """)
        actions_layout = QVBoxLayout(actions)
        
        actions_title = QLabel("Quick Actions")
        actions_title.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 10px;")
        
        # Create action buttons
        inject_btn = QPushButton(qta.icon('fa5s.syringe'), " Script Injection")
        inject_btn.clicked.connect(lambda: self.switch_page('inject'))
        
        browse_btn = QPushButton(qta.icon('fa5s.cloud-download-alt'), " Browse CodeShare")
        browse_btn.clicked.connect(lambda: self.switch_page('codeshare'))
        
        favorites_btn = QPushButton(qta.icon('fa5s.star'), " View Favorites")
        favorites_btn.clicked.connect(lambda: self.switch_page('favorites'))
        
        monitor_btn = QPushButton(qta.icon('fa5s.desktop'), " Process Monitor")
        monitor_btn.clicked.connect(lambda: self.switch_page('monitor'))
        
        actions_layout.addWidget(actions_title)
        actions_layout.addWidget(inject_btn)
        actions_layout.addWidget(browse_btn)
        actions_layout.addWidget(favorites_btn)
        actions_layout.addWidget(monitor_btn)
        
        # Add sections to main layout
        layout.addWidget(header)
        layout.addWidget(actions)
        layout.addStretch()
        
        return page
        
    def create_injection_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Add device selector
        self.device_selector = DeviceSelector()
        self.script_editor = ScriptEditorPanel()
        self.injection_panel = InjectionPanel()
        self.injection_panel.script_editor = self.script_editor
        self.output_panel = OutputPanel()
        
        layout.addWidget(self.device_selector)
        layout.addWidget(self.script_editor)
        layout.addWidget(self.injection_panel)
        layout.addWidget(self.output_panel)
        
        # Connect signals - ensure we're passing both device_id and pid
        self.device_selector.process_selected.connect(
            lambda device_id, pid: self.injection_panel.set_process(device_id, pid)
        )
        self.injection_panel.injection_started.connect(self.inject_script)
        self.injection_panel.injection_stopped.connect(self.stop_injection)
        
        return page
        
    def create_codeshare_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        self.codeshare_browser = CodeShareBrowser()
        # Connect codeshare signals here, after creating the browser
        self.codeshare_browser.open_in_injector.connect(self.open_script_in_injector)
        layout.addWidget(self.codeshare_browser)
        
        return page
        
    def create_favorites_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Toolbar
        toolbar = QHBoxLayout()
        
        # Search bar
        search_input = QLineEdit()
        search_input.setPlaceholderText("⌕ Search favorites...")
        search_input.textChanged.connect(self.filter_favorites)
        
        # Upload button
        upload_btn = QPushButton(qta.icon('fa5s.file-upload'), "Upload Script")
        upload_btn.clicked.connect(self.upload_script)
        
        toolbar.addWidget(search_input)
        toolbar.addWidget(upload_btn)
        
        # Grid for favorite scripts
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: #36393f;
            }
        """)
        
        self.favorites_grid = QWidget()
        self.favorites_grid_layout = QGridLayout(self.favorites_grid)
        self.favorites_grid_layout.setSpacing(10)
        scroll.setWidget(self.favorites_grid)
        
        # Add components to layout
        layout.addLayout(toolbar)
        layout.addWidget(scroll)
        
        # Initial population
        self.refresh_favorites()
        
        return page
        
    def filter_favorites(self, text):
        """Filter favorite scripts by search text"""
        search_text = text.lower()
        for i in range(self.favorites_grid_layout.count()):
            widget = self.favorites_grid_layout.itemAt(i).widget()
            if widget:
                title = widget.findChild(QLabel).text().lower()
                desc = widget.findChildren(QLabel)[-2].text().lower()
                widget.setVisible(search_text in title or search_text in desc)
                
    def upload_script(self):
        """Upload a custom script to favorites"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Upload Script",
            "",
            "JavaScript Files (*.js);;All Files (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    script_content = f.read()
                    
                # Create script info
                script_name = os.path.basename(file_path)
                script_info = {
                    'id': f"custom/{script_name}",
                    'title': script_name,
                    'author': 'Custom Script',
                    'description': 'Uploaded custom script',
                    'likes': 0,
                    'seen': 0,
                    'content': script_content
                }
                
                # Add to favorites
                self.add_to_favorites(script_info)
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to upload script: {str(e)}")
                
    def add_to_favorites(self, script_info):
        """Add a script to favorites"""
        # Add to favorites list if not already present
        if not any(s['id'] == script_info['id'] for s in self.favorites):
            self.favorites.append(script_info)
            self.save_favorites()

        # Create card widget
        card = self.create_favorite_card(script_info)
        
        # Add to grid
        count = self.favorites_grid_layout.count()
        row = count // 3
        col = count % 3
        self.favorites_grid_layout.addWidget(card, row, col)
        
    def create_favorite_card(self, script_info):
        """Create a card widget for a favorite script"""
        card = QFrame()
        card.setStyleSheet("""
            QFrame {
                background-color: #2f3136;
                border-radius: 8px;
                padding: 10px;
            }
            QFrame:hover {
                background-color: #40444b;
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Title and metadata
        title = QLabel(script_info['title'])
        title.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        author = QLabel(f"by {script_info['author']}")
        author.setStyleSheet("color: #b9bbbe;")
        
        # Description
        desc = QLabel(script_info.get('description', '')[:100] + '...')
        desc.setWordWrap(True)
        desc.setStyleSheet("color: #b9bbbe;")
        
        # Action buttons
        buttons = QHBoxLayout()
        
        view_btn = QPushButton("View")
        view_btn.clicked.connect(lambda: self.view_favorite(script_info))
        
        inject_btn = QPushButton("⚡ Inject")
        inject_btn.clicked.connect(lambda: self.open_script_in_injector(script_info.get('content', '')))
        
        remove_btn = QPushButton("✕ Remove")
        remove_btn.clicked.connect(lambda: self.remove_from_favorites(script_info, card))
        
        buttons.addWidget(view_btn)
        buttons.addWidget(inject_btn)
        buttons.addWidget(remove_btn)
        buttons.addStretch()
        
        # Add all components
        layout.addWidget(title)
        layout.addWidget(author)
        layout.addWidget(desc)
        layout.addLayout(buttons)
        
        return card
        
    def view_favorite(self, script_info):
        """View a favorite script's details"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"View Script - {script_info['title']}")
        dialog.resize(800, 600)
        
        layout = QVBoxLayout(dialog)
        
        # Script content
        content = QTextEdit()
        content.setReadOnly(True)
        content.setFont(QFont('Consolas', 11))
        content.setText(script_info.get('content', 'Script content not available'))
        
        # Action buttons
        buttons = QHBoxLayout()
        
        copy_btn = QPushButton(" Copy")
        copy_btn.clicked.connect(lambda: self.copy_to_clipboard(content.toPlainText()))
        
        inject_btn = QPushButton("⚡ Inject")
        inject_btn.clicked.connect(lambda: self.open_script_in_injector(content.toPlainText()))
        
        buttons.addWidget(copy_btn)
        buttons.addWidget(inject_btn)
        buttons.addStretch()
        
        layout.addWidget(content)
        layout.addLayout(buttons)
        
        dialog.exec_()
        
    def remove_from_favorites(self, script_info, card):
        """Remove a script from favorites"""
        reply = QMessageBox.question(
            self,
            "Remove Favorite",
            f"Remove {script_info['title']} from favorites?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Remove from grid
            card.setParent(None)
            
            # Remove from favorites list
            if script_info['id'].startswith('custom/'):
                self.favorites = [s for s in self.favorites if s['id'] != script_info['id']]
                self.save_favorites()
            elif hasattr(self.codeshare_browser, 'favorites'):
                self.codeshare_browser.favorites.remove(script_info['id'])
                self.codeshare_browser.save_favorites()
            
            # Refresh display
            self.refresh_favorites()
            
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "✓ Success", "📋 Copied to clipboard!")
        
    def create_history_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        self.history_page = HistoryPage(self.history_manager)
        self.history_page.script_selected.connect(self.open_script_in_injector)
        layout.addWidget(self.history_page)
        
        return page
        
    def create_monitor_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Pass self (main window) to ProcessMonitor
        self.process_monitor = ProcessMonitor(main_window=self)
        layout.addWidget(self.process_monitor)
        
        return page
        
    def create_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        
        # Add settings categories
        settings_categories = [
            ("General", [
                ("Auto-inject on launch", "checkbox"),
                ("Save script history", "checkbox"),
                ("Dark theme", "checkbox")
            ]),
            ("Script Editor", [
                ("Font size", "spinbox"),
                ("Show line numbers", "checkbox"),
                ("Auto-completion", "checkbox")
            ]),
            ("Monitoring", [
                ("Update interval", "spinbox"),
                ("Show memory usage", "checkbox"),
                ("Log to file", "checkbox")
            ])
        ]
        
        for category, settings in settings_categories:
            group = QGroupBox(category)
            group_layout = QVBoxLayout()
            
            for setting_name, setting_type in settings:
                setting_layout = QHBoxLayout()
                setting_layout.addWidget(QLabel(setting_name))
                
                if setting_type == "checkbox":
                    widget = QCheckBox()
                elif setting_type == "spinbox":
                    widget = QSpinBox()
                
                setting_layout.addWidget(widget)
                group_layout.addLayout(setting_layout)
                
            group.setLayout(group_layout)
            layout.addWidget(group)
            
        layout.addStretch()
        
        return page
        
    def on_process_started(self, name, pid):
        self.status_text.setText(f"Process started: {name} ({pid})")
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(12, 12))
        
    def on_process_ended(self, name, pid):
        self.status_text.setText(f"Process ended: {name} ({pid})")
        self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#f04747').pixmap(12, 12))
        
    def on_memory_updated(self, pid, memory_mb):
        # Update memory usage in process monitor
        pass
        
    def inject_script(self, script_content, pid):
        """Inject script into process"""
        try:
            if not script_content:
                QMessageBox.warning(self, "Error", "No script to inject!")
                return
                
            # Update status
            self.status_text.setText(f"Injecting into PID: {pid}")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#faa61a').pixmap(12, 12))
            
            # Get device and process info
            device_id = self.device_selector.current_device
            process_info = self.device_selector.get_selected_process_info()
            
            if not process_info:
                raise Exception("No process selected")
                
            device = frida.get_device(device_id)
            
            # Check if Android device needs frida-server
            if device.type == 'usb':
                if not AndroidHelper.is_frida_running(device_id):
                    self.output_panel.append_output("[*] Starting frida-server on device...")
                    if not AndroidHelper.start_frida_server(device_id):
                        raise Exception("Failed to start frida-server")
                    self.output_panel.append_output("[+] frida-server started")
                    # Re-get device after starting server
                    device = frida.get_device(device_id)
            
            try:
                # Try to attach first
                session = device.attach(pid)
                self.output_panel.append_output(f"[+] Successfully attached to PID: {pid}")
            except frida.ProcessNotFoundError:
                # If attach fails, try to spawn
                try:
                    if device.type == 'local':
                        # For local processes, use executable path
                        import psutil
                        process = psutil.Process(pid)
                        executable = process.exe()
                        pid = device.spawn([executable])
                        self.output_panel.append_output(f"[+] Spawned process with PID: {pid}")
                    else:
                        # For Android/remote devices
                        if device.type == 'usb':
                            package_name = process_info['name']
                            pid = device.spawn([package_name])
                            self.output_panel.append_output(f"[+] Spawned Android app: {package_name}")
                        else:
                            pid = device.spawn([process_info['name']])
                            
                    session = device.attach(pid)
                    device.resume(pid)
                except Exception as e:
                    raise Exception(f"Failed to spawn process: {str(e)}")
                    
            # Create and load script
            script = session.create_script(script_content)
            
            def on_message(message, data):
                if message['type'] == 'send':
                    self.output_panel.append_output(f"[*] {message['payload']}")
                elif message['type'] == 'error':
                    self.output_panel.append_output(f"[!] {message['description']}")
                    
            script.on('message', on_message)
            script.load()
            
            # Update status on success
            self.status_text.setText(f"Successfully injected into PID: {pid}")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(12, 12))
            
            # Store session and script
            self.current_session = session
            self.current_script = script
            
            # Show success message
            self.output_panel.append_output(f"[+] Script loaded successfully")
            
            # Add history entry
            self.history_manager.add_entry('script_injection', {
                'script': script_content,
                'pid': pid,
                'device': device_id,
                'status': 'success'
            })
            
        except Exception as e:
            error_msg = f"Injection failed: {str(e)}"
            self.output_panel.append_output(f"[-] {error_msg}")
            QMessageBox.critical(self, "Error", error_msg)
            
            # Add history entry
            self.history_manager.add_entry('script_injection', {
                'script': script_content,
                'pid': pid,
                'device': device_id,
                'status': 'failed',
                'error': str(e)
            })
            
        finally:
            if hasattr(self, 'injection_panel'):
                self.injection_panel.reset_ui()
        
    def stop_injection(self):
        """Stop the current injection"""
        try:
            if hasattr(self, 'current_script') and self.current_script:
                self.current_script.unload()
            if hasattr(self, 'current_session') and self.current_session:
                self.current_session.detach()
                
            self.current_script = None
            self.current_session = None
            
            self.output_panel.append_output("[*] Script injection stopped")
            self.status_text.setText("Ready")
            self.status_icon.setPixmap(qta.icon('fa5s.circle', color='#43b581').pixmap(12, 12))
            
        except Exception as e:
            error_msg = f"Error stopping injection: {str(e)}"
            self.output_panel.append_output(f"[-] {error_msg}")
            QMessageBox.critical(self, "Error", error_msg)
        
    def on_process_selected(self, device_id, pid):
        self.current_device = device_id
        self.current_pid = pid
        self.status_text.setText(f"Selected PID: {pid} on device: {device_id}")
        
    def open_in_injector(self, device_id, pid):
        """Open the selected process in the injector tab"""
        # Switch to injector tab
        self.switch_page('inject')
        
        # Select the device and process
        self.device_selector.select_device(device_id)
        self.device_selector.select_process(pid)
        
    def open_script_in_injector(self, code):
        """Open a script in the injector page"""
        # Switch to injector page
        self.switch_page('inject')
        
        # Set the script content
        self.script_editor.set_script(code)
        
    def load_favorites(self):
        """Load favorites from file"""
        try:
            favorites_file = os.path.join(os.path.expanduser('~'), '.frida_gui', 'favorites.json')
            if os.path.exists(favorites_file):
                with open(favorites_file, 'r') as f:
                    data = json.load(f)
                    self.favorites = data.get('scripts', [])
        except Exception as e:
            print(f"Error loading favorites: {e}")
            self.favorites = []

    def save_favorites(self):
        """Save favorites to file"""
        try:
            favorites_file = os.path.join(os.path.expanduser('~'), '.frida_gui', 'favorites.json')
            os.makedirs(os.path.dirname(favorites_file), exist_ok=True)
            with open(favorites_file, 'w') as f:
                json.dump({'scripts': self.favorites}, f)
        except Exception as e:
            print(f"Error saving favorites: {e}")

    def refresh_favorites(self):
        """Refresh the favorites page"""
        # Clear existing grid
        for i in reversed(range(self.favorites_grid_layout.count())): 
            widget = self.favorites_grid_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        # Get all favorites
        try:
            # Combine CodeShare favorites and custom scripts
            all_favorites = []
            
            # Add CodeShare favorites
            if hasattr(self.codeshare_browser, 'favorites'):
                response = requests.get(self.codeshare_browser.api_url)
                codeshare_scripts = response.json()
                for script in codeshare_scripts:
                    if script['id'] in self.codeshare_browser.favorites:
                        all_favorites.append(script)

            # Add custom scripts from our favorites
            all_favorites.extend([s for s in self.favorites if s['id'].startswith('custom/')])

            if all_favorites:
                # Add scripts to grid
                for idx, script_info in enumerate(all_favorites):
                    row = idx // 3
                    col = idx % 3
                    card = self.create_favorite_card(script_info)
                    self.favorites_grid_layout.addWidget(card, row, col)
            else:
                # Show message if no favorites
                msg = QLabel("No favorite scripts yet.\nBrowse scripts and click the ★ to add favorites!")
                msg.setAlignment(Qt.AlignCenter)
                msg.setStyleSheet("""
                    color: #b9bbbe;
                    font-size: 14px;
                    padding: 20px;
                """)
                self.favorites_grid_layout.addWidget(msg, 0, 0, 1, 3)

        except Exception as e:
            error_msg = QLabel(f"Error loading favorites: {str(e)}")
            error_msg.setStyleSheet("color: #ff4444;")
            self.favorites_grid_layout.addWidget(error_msg, 0, 0, 1, 3)