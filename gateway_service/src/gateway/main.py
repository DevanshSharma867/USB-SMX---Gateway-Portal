# Main entry point for the Gateway Service.
import sys
import time
from pathlib import Path

# Add the src directory to the Python path to allow for module imports
SRC_PATH = Path(__file__).parent.parent
sys.path.insert(0, str(SRC_PATH))

from gateway.device_manager import DeviceManager

def main():
    """Initializes and runs the device manager."""
    print("--- SMX Gateway Service MVP ---")
    manager = DeviceManager()
    manager.start_monitoring()
    
    print("Monitoring for USB devices. Press Ctrl+C to stop.")
    try:
        # Keep the main thread alive to allow the monitoring thread to run.
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Shutdown signal received. Stopping monitor...")
        manager.stop_monitoring()
        print("Gateway Service stopped.")

if __name__ == '__main__':
    main()
