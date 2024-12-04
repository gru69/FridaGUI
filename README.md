

# FridaGUI

A modern and powerful GUI tool for Frida script management and injection, created by **Oliver Stankiewicz**.

## 🚀 Features
- 🔍 **Script Injection with Live Preview**
- 🌐 **CodeShare Browser & Integration**
- ⭐ **Favorites System**
- 📱 **Android/iOS Device Support**
- 💻 **Process Management**
- 🎨 **Modern Dark Theme UI**
- 📊 **Real-time Process Monitoring**
- 📝 **Script History Tracking**
- 🔄 **Auto-injection Support**

---

## 📥 Installation

### Prerequisites
- **Python 3.8+**
- **Frida**
- **ADB** (for Android device support)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/oliverstankiewicz/FridaGUI.git
   cd FridaGUI
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application:
   ```bash
   python src/main.py
   ```

---

## 📂 Project Structure
```
FridaGUI/
├── src/
│   ├── gui/
│   │   ├── widgets/
│   │   │   ├── device_panel.py
│   │   │   ├── data_visualizer.py
│   │   │   ├── history_page.py
│   │   │   ├── injection_panel.py
│   │   │   ├── output_panel.py
│   │   │   ├── process_monitor.py
│   │   │   ├── process_panel.py
│   │   │   └── script_editor.py
│   │   └── main_window.py
│   ├── utils/
│   │   └── themes.py
│   └── main.py
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── README.md
```

---

## 🧩 Core Components

### **Device Panel**
- USB/Network device support
- Android device detection
- Frida server management
- Process listing

### **Script Editor**
- Code editing with syntax highlighting
- Script management and injection controls
- Real-time output monitoring

### **Process Monitor**
- Real-time process list with filtering
- Memory tracking and auto-refresh

### **Data Visualizer**
- Process data visualization
- Memory usage graphs and performance metrics
- Real-time updates

### **History Page**
- Script history and injection logs
- Quick re-injection functionality
- Session tracking

---

## 📜 Dependencies
- Refer to the `requirements.txt` file for a complete list of dependencies.

---

## 📄 License
This project is licensed under the **agplv3 License**. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author
**Oliver Stankiewicz**

---

## 🤝 Contributing
Pull requests are welcome! For major changes, please open an issue first to discuss your ideas.

---

## 🛠️ Support
If you encounter any issues or have questions, please file an issue on [GitHub](https://github.com/oliverstankiewicz/FridaGUI/issues).
