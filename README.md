# loard

[![Python 3.8.10+](https://img.shields.io/badge/Python-3.8.10+-green.svg?style=flat-square)](https://www.python.org/downloads/release/python-3810/)
![OS](https://img.shields.io/badge/Tested%20On-Linux%20%7C%20Windows%20%7C%20macOS-yellowgreen.svg?style=flat-square)
![Python](https://img.shields.io/badge/python-3670A0?logo=python&logoColor=ffdd54)
[![Internet](https://img.shields.io/badge/internet-4285F4?logo=google-chrome&logoColor=white)](https://img.shields.io/badge/wi--fi-007BFF?logo=rss&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**loard** is an open-source utility for scanning and displaying detailed information about your local network and Wi-Fi connections. It allows you to view Wi-Fi networks, retrieve saved passwords (only for networks you're connected to or have access to), scan devices on your local subnet, and log the results. The tool creates a `log` folder either in the current directory or on connected drives (e.g., H: or G: on Windows, or mounted volumes on Linux/macOS).

## Table of Contents

- [Installation](#installation)
- [Features](#features)
- [Requirements](#requirements)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [License](#license)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/toploardgg/loard.git
   cd loard
   ```

2. Install dependencies:

   ```bash
   python3 install.py
   ```

   This script will handle pip installations for the required libraries. If you encounter issues, install them manually with `pip install <library>`.

3. Run the tool:
   - CLI version: `python3 loard.py`
   - GUI version: `python3 loard_gui.py` (assuming a GUI script exists; adjust if named differently).

Key features include:
- Wi-Fi network scanning and password retrieval (for saved profiles).
- Local network device discovery (IP, MAC, hostname, vendor).
- Logging to files for easy review.
- Support for both CLI (command-line interface) and GUI versions.

This tool is designed for educational and personal use on your own systems. It requires administrative privileges for some features and works across Windows, Linux, and macOS.

## Features

- **Wi-Fi Scanning**: Detects available Wi-Fi networks and retrieves passwords from saved profiles (only shown if connected or accessible).
- **Network Device Scanning**: Scans your local subnet for connected devices, displaying IP addresses, MAC addresses, hostnames, and vendors.
- **Logging**: Automatically creates a `log` folder and saves scan results in timestamped text files. Logs are saved near the script or on external drives if detected.
- **System Information**: Displays local IP, gateway, DNS servers, external IP, and active connections.
- **Cross-Platform**: Tested on Windows, Linux, and macOS.
- **Versions**: Available in CLI (terminal-based) and GUI modes.
- **Safety Features**: Includes a mount watcher to handle removable drives gracefully.

Note: Passwords are only accessible for networks stored on your device. This tool does not crack or hack networks—it only reads local system data.

## Requirements

- Python 3.8.10 or higher.
- Required libraries (installed via `install.py` or manually):
  - `psutil`
  - `requests`
  - `pandas`
  - `tqdm`
  - `colorama`
  - `scapy` (optional, for advanced network scanning; if not installed, falls back to basic methods)
  - `netifaces`
- Administrative privileges (sudo on Linux/macOS) for some network commands.
- Wi-Fi adapter enabled on your device.
- Internet access for external IP lookup (optional).

## Usage

1. Launch the script in your terminal or console.
2. It will scan for available Wi-Fi networks and prompt you to select one by number.
3. After selection, it displays detailed network info, device scans, and logs the results.
4. Press Enter to refresh or 'q' to quit.
5. If no networks are found, ensure your Wi-Fi is enabled and try again.

Example output includes:
- Local IP, Gateway, Subnet, DNS, External IP.
- Active connections.
- List of devices with IP, MAC, Vendor, Hostname, and associated passkey.

Logs are saved in `./log/` or on detected external drives for portability.

## Screenshots

![Wi-Fi Scan Example](loard.png)
![GUI Interface](loardgui.png)
![Device Scan](loard1.png)
![Log Output](loard2.png)

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests for bug fixes, features, or improvements. Please follow standard GitHub workflows.

## Disclaimer

This tool is for educational purposes only. Use it responsibly on your own networks and devices. The authors are not responsible for any misuse, data loss, or legal issues arising from its use. Always comply with local laws regarding network scanning and data access.

Made by Toploardgg
