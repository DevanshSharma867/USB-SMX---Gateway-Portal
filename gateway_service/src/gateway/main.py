# Main entry point for the Gateway Service.
import sys
import time
import queue
from pathlib import Path

# Add the src directory to the Python path to allow for module imports
SRC_PATH = Path(__file__).parent.parent
sys.path.insert(0, str(SRC_PATH))

from gateway.device_manager import DeviceManager
from gateway.gui import GuiManager

def main():
    """Initializes and runs the background monitor and the GUI manager."""
    print("--- SMX Gateway Service with GUI --- ")
    
    # 1. Create a queue for communication between the backend and GUI
    gui_queue = queue.Queue()

    # 2. Initialize the GUI Manager in the main thread
    gui_manager = GuiManager(gui_queue)

    # 3. Initialize the Device Manager and pass it the queue
    device_manager = DeviceManager(gui_queue)
    
    # 4. Start the background thread for device monitoring
    device_manager.start_monitoring()
    
    print("Monitoring for USB devices. GUI will pop up on insertion.")

    # 5. Start the GUI main loop. This will block the main thread.
    try:
        gui_manager.start()
    except KeyboardInterrupt:
        print("Shutdown signal received.")
    finally:
        # Cleanly stop the monitoring thread
        print("Stopping monitor...")
        device_manager.stop_monitoring()
        print("Gateway Service stopped.")

if __name__ == '__main__':
    main()