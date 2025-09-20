# Gateway Portal

A secure gateway service implementation for managing encrypted data transfer and device communications.

## Project Structure

```
gateway_service/
├── decrypt_job.py
├── src/
│   └── gateway/
│       ├── crypto.py
│       ├── device_manager.py
│       ├── file_processor.py
│       ├── gui.py
│       ├── job_manager.py
│       └── main.py
└── tests/
    ├── test_crypto.py
    ├── test_device_manager.py
    ├── test_file_processor.py
    ├── test_integration.py
    └── test_job_manager.py
```

## Features

- Secure file encryption and decryption
- Device management and communication
- Job processing and management
- File processing capabilities
- Graphical user interface
- Comprehensive test coverage

## Requirements

See `src/requirements.txt` for detailed Python package dependencies.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/DevanshSharma867/USB-SMX---Gateway-Portal.git
```

2. Navigate to the project directory:
```bash
cd gateway_service
```

3. Install required dependencies:
```bash
pip install -r src/requirements.txt
```

## Usage

To start the Gateway Portal application:

```bash
python -m gateway.main
```

## Testing

Run the test suite using:

```bash
python -m pytest tests/
```

## Project Structure Details

- `decrypt_job.py`: Handles decryption operations
- `src/gateway/`:
  - `crypto.py`: Cryptographic operations implementation
  - `device_manager.py`: Device communication and management
  - `file_processor.py`: File handling and processing
  - `gui.py`: Graphical user interface implementation
  - `job_manager.py`: Job scheduling and management
  - `main.py`: Main application entry point

## Contact

- Developer: Devansh Sharma
- Repository: [USB-SMX---Gateway-Portal](https://github.com/DevanshSharma867/USB-SMX---Gateway-Portal)