import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                  QHBoxLayout, QComboBox, QPushButton, QTextEdit, 
                            QLabel, QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import frida
import subprocess
import time
import os
import requests
import platform
import lzma

class FridaWorker(QThread):
    output_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)
    
    def __init__(self, action, **kwargs):
        super().__init__()
        self.action = action
        self.kwargs = kwargs

    def run(self):
        try:
            if self.action == "scan_devices":
                self._scan_devices()
            elif self.action == "inject":
                self._inject_script()
            elif self.action == "launch":
                self._launch_app()
        except Exception as e:
            self.error_signal.emit(str(e))

    def _scan_devices(self):
        try:
            # Kill and restart ADB server
            subprocess.run(['adb', 'kill-server'], capture_output=True)
            time.sleep(1)
            subprocess.run(['adb', 'start-server'], capture_output=True)
            time.sleep(2)

            # Try connecting to Nox
            nox_ports = ['62001', '62025', '62026', '62027', '62028', '62029']
            for port in nox_ports:
                try:
                    subprocess.run(['adb', 'connect', f'127.0.0.1:{port}'], 
                                 capture_output=True)
                except:
                    continue

            time.sleep(2)
            self.output_signal.emit("Device scan completed")
        except Exception as e:
            self.error_signal.emit(f"Error scanning devices: {str(e)}")

    def _inject_script(self):
        try:
            device_id = self.kwargs['device_id']
            process_id = self.kwargs['process_id']
            script_content = self.kwargs['script']
            
            # Special handling for Nox
            if '127.0.0.1' in device_id:
                # Ensure frida-server is running
                try:
                    subprocess.run(['adb', '-s', device_id, 'shell', 'su -c "killall -9 frida-server"'], 
                                 capture_output=True)
                    time.sleep(1)
                    subprocess.Popen(['adb', '-s', device_id, 'shell', 'su -c "/data/local/tmp/frida-server &"'],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.output_signal.emit("Restarted frida-server on Nox")
                    time.sleep(3)
                except Exception as e:
                    self.error_signal.emit(f"Error restarting frida-server: {str(e)}")

            # Try to attach multiple times
            max_retries = 3
            last_error = None
            
            for i in range(max_retries):
                try:
                    device = frida.get_device(device_id)
                    session = device.attach(int(process_id))
                    script = session.create_script(script_content)

                    def on_message(message, data):
                        if message['type'] == 'send':
                            self.output_signal.emit(f"Script message: {message['payload']}")
                        elif message['type'] == 'error':
                            self.error_signal.emit(f"Script error: {message['description']}")

                    script.on('message', on_message)
                    script.load()
                    self.output_signal.emit("Script injected successfully")
                    return
                except Exception as e:
                    last_error = str(e)
                    self.output_signal.emit(f"Injection attempt {i+1} failed, retrying...")
                    time.sleep(2)
                    continue

            raise Exception(f"Failed after {max_retries} attempts. Last error: {last_error}")

        except Exception as e:
            self.error_signal.emit(f"Injection error: {str(e)}")

    def _launch_app(self):
        try:
            device_id = self.kwargs['device_id']
            package_name = self.kwargs['package_name']
            script_content = self.kwargs['script']
            
            # Special handling for Nox
            if '127.0.0.1' in device_id:
                try:
                    # Setup frida-server first
                    if not self.setup_frida_server(device_id):
                        raise Exception("Failed to setup frida-server")
                    
                    # Ensure connection to Nox
                    subprocess.run(['adb', 'connect', device_id], capture_output=True)
                    time.sleep(1)
                    
                    # Start frida-server
                    subprocess.run(['adb', '-s', device_id, 'shell', 'su -c "killall -9 frida-server"'], 
                                 capture_output=True)
                    time.sleep(1)
                    subprocess.Popen(['adb', '-s', device_id, 'shell', 'su -c "/data/local/tmp/frida-server &"'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.output_signal.emit("Started frida-server on Nox")
                    time.sleep(3)

                    # Kill existing app
                    subprocess.run(['adb', '-s', device_id, 'shell', 'am force-stop ' + package_name], 
                                 capture_output=True)
                    time.sleep(1)

                    # Get device and spawn app
                    device = frida.get_device(device_id)
                    pid = device.spawn([package_name])
                    self.output_signal.emit(f"Spawned app with PID: {pid}")
                    
                    # Attach to the spawned process
                    session = device.attach(pid)
                    
                    # Create and load script
                    script = session.create_script(script_content)
                    
                    def on_message(message, data):
                        if message['type'] == 'send':
                            self.output_signal.emit(f"Script message: {message['payload']}")
                        elif message['type'] == 'error':
                            self.error_signal.emit(f"Script error: {message['description']}")
                    
                    script.on('message', on_message)
                    script.load()
                    self.output_signal.emit("Script loaded")
                    
                    # Resume the app
                    device.resume(pid)
                    self.output_signal.emit("App resumed with injected script")
                    
                except Exception as e:
                    raise Exception(f"Nox launch failed: {str(e)}")
            
            self.output_signal.emit("App launched successfully with script")
        except Exception as e:
            self.error_signal.emit(f"Launch error: {str(e)}")

    def download_frida_server(self):
        try:
            # Get device architecture
            device_id = self.kwargs.get('device_id', '')
            abi = subprocess.check_output(
                ['adb', '-s', device_id, 'shell', 'getprop', 'ro.product.cpu.abi'],
                text=True
            ).strip()

            # Map Android ABI to Frida architecture
            abi_to_arch = {
                'arm64-v8a': 'arm64',
                'armeabi-v7a': 'arm',
                'x86': 'x86',
                'x86_64': 'x86_64'
            }
            arch = abi_to_arch.get(abi, 'arm64')

            # Get latest Frida release version
            response = requests.get('https://api.github.com/repos/frida/frida/releases/latest')
            latest_version = response.json()['tag_name']
            
            # Construct download URL
            download_url = f'https://github.com/frida/frida/releases/download/{latest_version}/frida-server-{latest_version[0:]}-android-{arch}.xz'
            self.output_signal.emit(f"Downloading Frida server from: {download_url}")
            
            # Download frida-server
            response = requests.get(download_url)
            response.raise_for_status()
            
            # Decompress XZ file
            decompressed_data = lzma.decompress(response.content)
            
            # Save as frida-server in current directory
            frida_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-server')
            with open(frida_path, 'wb') as f:
                f.write(decompressed_data)
            
            # Make executable
            os.chmod(frida_path, 0o755)
            
            self.output_signal.emit(f"Successfully downloaded frida-server {latest_version}")
            return frida_path
        except Exception as e:
            self.error_signal.emit(f"Error downloading frida-server: {str(e)}")
            return None

    def setup_frida_server(self, device_id):
        try:
            # Check if frida-server exists locally
            frida_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'frida-server')
            if not os.path.exists(frida_path):
                self.output_signal.emit("Downloading frida-server...")
                frida_path = self.download_frida_server()
                if not frida_path:
                    raise Exception("Failed to download frida-server")

            # Push frida-server to device
            self.output_signal.emit("Pushing frida-server to device...")
            result = subprocess.run(
                ['adb', '-s', device_id, 'push', frida_path, '/data/local/tmp/'],
                capture_output=True,
                text=True
            )
            
            if "error" in result.stderr.lower():
                # Try with su if normal push fails
                self.output_signal.emit("Trying with root permissions...")
                subprocess.run(['adb', '-s', device_id, 'shell', 'su -c "mount -o rw,remount /system"'])
                subprocess.run(['adb', '-s', device_id, 'shell', 'su -c "chmod 777 /data/local/tmp"'])
                subprocess.run(['adb', '-s', device_id, 'push', frida_path, '/data/local/tmp/'])

            # Set permissions
            subprocess.run(['adb', '-s', device_id, 'shell', 'su -c "chmod 755 /data/local/tmp/frida-server"'])
            
            self.output_signal.emit("Frida server setup completed")
            return True
        except Exception as e:
            self.error_signal.emit(f"Error setting up frida-server: {str(e)}")
            return False

class FridaGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Frida Script Injector")
        self.setMinimumSize(800, 600)
        
        # Create main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Device selection
        device_layout = QHBoxLayout()
        self.device_combo = QComboBox()
        scan_button = QPushButton("Scan Devices")
        scan_button.clicked.connect(self.scan_devices)
        device_layout.addWidget(QLabel("Select Device:"))
        device_layout.addWidget(self.device_combo)
        device_layout.addWidget(scan_button)
        layout.addLayout(device_layout)

        # Process selection
        process_layout = QHBoxLayout()
        self.process_combo = QComboBox()
        list_button = QPushButton("List Processes")
        list_button.clicked.connect(self.list_processes)
        process_layout.addWidget(QLabel("Select Process:"))
        process_layout.addWidget(self.process_combo)
        process_layout.addWidget(list_button)
        layout.addLayout(process_layout)

        # Launch button
        launch_button = QPushButton("Launch App")
        launch_button.clicked.connect(self.launch_app)
        layout.addWidget(launch_button)

        # Launch with inject checkbox
        self.inject_on_launch = QCheckBox("Inject on Launch")
        self.inject_on_launch.setChecked(True)  # Enable by default
        layout.addWidget(self.inject_on_launch)

        # Script editor
        layout.addWidget(QLabel("Frida Script:"))
        self.script_editor = QTextEdit()
        self.script_editor.setPlainText('''Java.perform(function() {
    console.log("Loaded!");
    // Enable SSL logging
    var modules = Process.enumerateModules();
    modules.forEach(function(module) {
        if (module.name.indexOf(".so") !== -1) {
            console.log("Module " + module.name + " SSL logging started.");
        }
    });
});''')
        layout.addWidget(self.script_editor)

        # Output area
        layout.addWidget(QLabel("Output:"))
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        # Initial device scan
        self.scan_devices()

    def log_output(self, message):
        self.output_area.append(message)

    def scan_devices(self):
        self.worker = FridaWorker("scan_devices")
        self.worker.output_signal.connect(self.log_output)
        self.worker.error_signal.connect(self.log_output)
        self.worker.finished.connect(self._update_devices)
        self.worker.start()

    def _update_devices(self):
        try:
            self.device_combo.clear()
            devices = frida.enumerate_devices()
            for device in devices:
                self.device_combo.addItem(f"{device.name} ({device.type})", device.id)
        except Exception as e:
            self.log_output(f"Error updating devices: {str(e)}")

    def list_processes(self):
        try:
            device_id = self.device_combo.currentData()
            if not device_id:
                raise Exception("Please select a device first")

            device = frida.get_device(device_id)
            
            # Get installed packages instead of processes
            packages = []
            adb_output = subprocess.check_output(
                ['adb', '-s', device_id, 'shell', 'pm', 'list', 'packages', '-f'],
                text=True
            ).strip().split('\n')
            
            self.process_combo.clear()
            for line in adb_output:
                if line:
                    # Extract package name from line
                    package = line.split('=')[-1]
                    # Get app name using aapt
                    try:
                        app_path = line.split(':')[1].split('=')[0]
                        aapt_output = subprocess.check_output(
                            ['adb', '-s', device_id, 'shell', 'dumpsys', 'package', package],
                            text=True
                        )
                        app_name = package  # Default to package name
                        for line in aapt_output.split('\n'):
                            if 'applicationInfo' in line and 'label=' in line:
                                app_name = line.split('label=')[1].split(' ')[0]
                                break
                        
                        self.process_combo.addItem(f"{app_name} ({package})", package)
                    except:
                        # If we can't get the app name, just show package name
                        self.process_combo.addItem(package, package)
                    
            self.log_output("Applications listed successfully")
        except Exception as e:
            self.log_output(f"Error listing applications: {str(e)}")

    def launch_app(self):
        try:
            device_id = self.device_combo.currentData()
            package_name = self.process_combo.currentData()
            script = self.script_editor.toPlainText() if self.inject_on_launch.isChecked() else ""
            
            if not device_id or not package_name:
                raise Exception("Please select device and application first")

            if self.inject_on_launch.isChecked() and not script:
                raise Exception("Please provide a script to inject")

            self.worker = FridaWorker("launch", 
                                    device_id=device_id,
                                    package_name=package_name,
                                    script=script)
            self.worker.output_signal.connect(self.log_output)
            self.worker.error_signal.connect(self.log_output)
            self.worker.start()
        except Exception as e:
            self.log_output(f"Error launching app: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = FridaGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main()
