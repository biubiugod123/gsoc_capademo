# Android CAPA Frida Logger

A tool for dynamic analysis of Android applications that creates JSON output compatible with CAPA's FridaExtractor for behavior-based malware analysis.

## Overview

This project provides a comprehensive framework for monitoring Android application behaviors at runtime using Frida instrumentation. It captures API calls and system interactions, then formats the data in a way that's compatible with CAPA analysis tools for malware capability detection.

Key features:
- Dynamic API call monitoring using Frida
- Detection of security-relevant behaviors including:
  - Network operations
  - File system access
  - SMS operations
  - Device information collection
  - Cryptographic operations
  - Content provider access
  - Location tracking
  - Camera usage
  - Shell command execution
  - Package enumeration
  - WebView JavaScript interactions
- JSON output compatible with CAPA rules
- Automatic package name resolution
- Configurable runtime monitoring

## Prerequisites

- Python 3.6+
- Frida CLI tools (`frida-ps`, `frida`)
- Android device (physical or emulator) with USB debugging enabled
- [CAPA](https://github.com/mandiant/capa) tool (optional, for analysis)

## Installation

1. Clone this repository:
```
git clone https://github.com/yourusername/android-capa-frida.git
cd android-capa-frida
```

2. Install required Python dependencies:
```
pip install frida frida-tools
```

3. Make sure your Android device is connected with USB debugging enabled:
```
adb devices
```

## Usage

The main script is `capa_frida.py`, which uses `frida_android_hooks.js` to instrument Android applications.

### Basic usage

```
python capa_frida.py -p <package_name>
```

You can provide either a full package name (e.g., `com.example.app`) or a search term to find the target application.

### Advanced options

```
python capa_frida.py -p <package_name> -d <device_id> -o <output_file> -s <script_path> -t <timeout>
```

Parameters:
- `-p, --package`: Application package name or search term
- `-d, --device`: Target specific device ID (optional)
- `-o, --output`: Output JSON file path (default: `frida_capa.json`)
- `-s, --script`: Path to Frida hook script (default: `frida_android_hooks.js`)
- `-t, --timeout`: How long to run Frida in seconds (default: 60)

### Example

```
python capa_frida.py -p diva -t 120 -o diva_analysis.json
```

This will:
1. Find and launch the DIVA (Damn Insecure and Vulnerable App)
2. Monitor it for 120 seconds while you interact with it
3. Save the captured behaviors to `diva_analysis.json`

## CAPA Rules

The repository includes sample CAPA rules in the YAML format:

- `device_info.yml`: Detects when apps gather device information
- `premium.yml`: Identifies apps that send SMS messages to premium numbers

You can use these rules with CAPA to analyze the captured behaviors:

```
capa -r rules/ frida_capa.json
```

## How It Works

1. The Python script (`capa_frida.py`) identifies the target application and prepares the environment
2. It injects the JavaScript hooks (`frida_android_hooks.js`) into the application process
3. As you interact with the app, the hooks capture API calls and system interactions
4. The data is sent back to the Python script and stored in JSON format
5. The output can be analyzed with CAPA to identify capabilities and potentially malicious behaviors

## Troubleshooting

- **No application found**: Try providing the full package name instead of a search term
- **No events captured**: Make sure you interact with the application to trigger behaviors
- **Frida crashes**: Some applications may have anti-tampering protections; try running with the `-t` flag to set a shorter timeout



## Acknowledgments

- [Frida](https://frida.re/) for the dynamic instrumentation toolkit
- [CAPA](https://github.com/mandiant/capa) for the behavior-based malware analysis framework
- The Android security research community