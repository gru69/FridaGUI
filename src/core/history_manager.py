from datetime import datetime
import json
import os

class HistoryManager:
    def __init__(self):
        self.history_file = os.path.join(os.path.expanduser('~'), '.frida_gui', 'history.json')
        self.history = self.load_history()
        
    def load_history(self):
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading history: {e}")
        return []
        
    def save_history(self):
        try:
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")
            
    def add_entry(self, action_type, details):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': action_type,
            'details': details
        }
        self.history.insert(0, entry)  # Add to start of list
        self.save_history()
        
    def clear_history(self):
        self.history = []
        self.save_history() 