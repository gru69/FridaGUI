# FridaGUI

A modern and powerful GUI tool for Frida script management and injection, created by Oliver Stankiewicz.

## Features
- 🔍 Script Injection with Live Preview
- 🌐 CodeShare Browser & Integration
- ⭐ Favorites System
- 📱 Android/iOS Device Support
- 💻 Process Management
- 🎨 Modern Dark Theme UI
- 📊 Real-time Process Monitoring
- 📝 Script History Tracking
- 🔄 Auto-injection Support
- 🧵 Multi-threaded Performance

## Installation

### Prerequisites
- Python 3.8+
- Frida
- ADB (for Android device support)

### Setup

Clone the repository
git clone https://github.com/oliverstankiewicz/FridaGUI.git
cd FridaGUI
Install dependencies
pip install -r requirements.txt
Run the application
python src/main.py
Structure
FridaGUI/
├── src/
│ ├── gui/
│ │ ├── widgets/
│ │ │ ├── device_panel.py
│ │ │ ├── data_visualizer.py
│ │ │ ├── history_page.py
│ │ │ ├── injection_panel.py
│ │ │ ├── output_panel.py
│ │ │ ├── process_monitor.py
│ │ │ ├── process_panel.py
│ │ │ └── script_editor.py
│ │ └── main_window.py
│ ├── utils/
│ │ └── themes.py
│ └── main.py
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── README.md



## Core Components

### Device Panel
- USB/Network device support
- Android device detection
- Frida server management
- Process listing

### Script Editor
- Code editing
- Script management
- Injection controls
- Output monitoring

### Process Monitor
- Real-time process list
- Process filtering
- Memory tracking
- Auto-refresh

### Data Visualizer
- Process data visualization
- Memory usage graphs
- Performance metrics
- Real-time updates

### History Page
- Script history
- Injection logs
- Quick re-injection
- Session tracking

## Dependencies
- See `requirements.txt` for main dependencies


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author
**Oliver Stankiewicz**

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Support
If you encounter any issues or have questions, please file an issue on GitHub.