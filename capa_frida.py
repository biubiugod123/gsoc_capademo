#!/usr/bin/env python3
"""
Frida CAPA Logger - Creates JSON output compatible with CAPA's FridaExtractor
(Fixed version to properly capture events with better SMS detection)
"""

import os
import sys
import json
import threading
import time
import argparse
import subprocess
import traceback
from pathlib import Path
from queue import Queue
from typing import Dict, Any, Optional, List

import frida
from _queue import Empty


def setup_frida(device_id: Optional[str] = None) -> bool:
    """
    Check if Frida is installed and a device is connected

    Args:
        device_id: Optional specific device ID to target

    Returns:
        bool: True if setup is successful
    """
    try:
        device_manager = frida.get_device_manager()
        devices = device_manager.enumerate_devices()
        print("[+] Connected devices:")
        for dev in devices:
            print(f"    {dev.id} ({dev.type})")
        return True
    except Exception as e:
        print(f"[-] Error listing devices: {e}")
        return False


def get_package_name(search_term: str, device_id: Optional[str] = None) -> Optional[str]:
    """
    Find an installed package on the device that matches the search term

    Args:
        search_term: Partial or full package name
        device_id: Optional specific device ID to target

    Returns:
        Optional[str]: Package name if found
    """
    print(f"[DEBUG] Searching for package matching '{search_term}'")

    cmd = ["frida-ps"]
    if device_id:
        cmd.extend(["-D", device_id])
    cmd.extend(["-Uai"])  # List all applications, installed, with USB connection

    print(f"[DEBUG] Running command: {' '.join(cmd)}")

    try:
        result = subprocess.run(cmd, capture_output=True, check=True, text=True)
        print(f"[DEBUG] Command output:\n{result.stdout}")

        # If the package name is passed directly and matches exactly, use it
        if search_term.startswith("jakhar.") or search_term.startswith("com."):
            # Check if this exact package exists
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts and parts[-1] == search_term:
                    print(f"[+] Found exact package match: {search_term}")
                    return search_term

        # Otherwise try partial matching
        matches = []
        for line in result.stdout.splitlines():
            if search_term.lower() in line.lower():
                parts = line.split()
                if len(parts) >= 1:
                    pkg_name = parts[-1]
                    matches.append(pkg_name)
                    print(f"[DEBUG] Found potential match: {pkg_name}")

        if matches:
            # If multiple matches, prefer the one with exact name match
            for pkg in matches:
                if search_term.lower() in pkg.lower():
                    print(f"[+] Selected package: {pkg}")
                    return pkg

            # Otherwise just return the first match
            print(f"[+] Selected package: {matches[0]}")
            return matches[0]

        print(f"[-] No package found matching '{search_term}'")
        return None
    except subprocess.SubprocessError as e:
        print(f"[-] Error listing packages: {e}")
        if hasattr(e, 'stderr'):
            print(f"[DEBUG] Error output: {e.stderr}")
        return None


def extract_api_events(logs):
    """
    Extract API events from a list of log lines
    """
    events = []
    for line in logs:
        if "'type': 'api_call'" in line:
            try:
                # Try to extract the JSON payload
                start_idx = line.find("{'type': ")
                if start_idx >= 0:
                    # Try to find the end of the object by counting braces
                    nested_level = 0
                    in_string = False
                    escape_next = False
                    payload_str = None

                    for i in range(start_idx, len(line)):
                        c = line[i]

                        if escape_next:
                            escape_next = False
                            continue

                        if c == '\\':
                            escape_next = True
                            continue

                        if c == "'" and not escape_next:
                            in_string = not in_string

                        if not in_string:
                            if c == '{':
                                nested_level += 1
                            elif c == '}':
                                nested_level -= 1
                                if nested_level == 0:
                                    payload_str = line[start_idx:i + 1]
                                    break

                    if payload_str:
                        # Convert to proper JSON (replace single quotes with double quotes)
                        payload_str = payload_str.replace("'", '"')
                        # Fix None values
                        payload_str = payload_str.replace(': None', ': null')
                        payload_str = payload_str.replace(': True', ': true')
                        payload_str = payload_str.replace(': False', ': false')
                        # Parse JSON
                        payload = json.loads(payload_str)
                        events.append(payload)
                        print(f"[+] Extracted event: {payload.get('api', 'unknown')}")
            except Exception as e:
                print(f"[!] Error extracting event: {e}")

    return events


def detect_sms_operations(logs):
    """
    Custom detector for SMS-related operations from logs
    """
    sms_events = []

    # Look for common SMS-related patterns
    sms_patterns = [
        ("content://sms", "SMS_ACCESS"),
        ("content://mms", "MMS_ACCESS"),
        ("SmsManager.sendTextMessage", "SMS_SEND"),
        ("phones/filter", "CONTACTS_QUERY"),
        ("mms-sms/threadID", "SMS_THREAD_ACCESS")
    ]

    for line in logs:
        for pattern, event_type in sms_patterns:
            if pattern in line:
                # Extract as much info as possible
                try:
                    if "'api':" in line:
                        api_start = line.find("'api':") + 7
                        api_end = line.find("'", api_start)
                        api = line[api_start:api_end]
                    else:
                        api = "Unknown"

                    if "'args':" in line:
                        args_start = line.find("'args':") + 7
                        args_end = line.find("]", args_start) + 1
                        args_str = line[args_start:args_end].replace("'", '"')
                        try:
                            args = json.loads(args_str)
                        except:
                            args = [pattern]
                    else:
                        args = [pattern]

                    event = {
                        "type": "api_call",
                        "api": api,
                        "category": event_type,
                        "args": args,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
                    }

                    sms_events.append(event)
                    print(f"[+] Detected SMS event: {event_type} via {api}")
                except Exception as e:
                    print(f"[!] Error creating SMS event: {e}")

    return sms_events


def run_frida(package_name: str, script_path: str, output_path: str,
              device_id: Optional[str] = None, timeout: int = 60) -> bool:
    cmd = ["frida"]
    if device_id:
        cmd.extend(["-D", device_id])
    cmd.extend(["-U", "-l", script_path, "-f", package_name])

    print(f"[DEBUG] Running command: {' '.join(cmd)}")
    print(f"[+] Starting Frida on {package_name}")
    print(f"[+] Will run for {timeout} seconds (Ctrl+C to stop earlier)")
    print(f"[+] Interact with the app to trigger behaviors...")

    events = []
    proc = None

    try:
        proc = subprocess.Popen(cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                                bufsize=1,
                                universal_newlines=True)

        # Queues for stdout and stderr
        stdout_queue = Queue()
        stderr_queue = Queue()

        # Thread function to read lines and put them in a queue
        def read_output(pipe, queue):
            for line in iter(pipe.readline, ''):
                queue.put(line)
            pipe.close()

        # Start threads for stdout and stderr
        stdout_thread = threading.Thread(target=read_output, args=(proc.stdout, stdout_queue))
        stdout_thread.daemon = True
        stdout_thread.start()

        stderr_thread = threading.Thread(target=read_output, args=(proc.stderr, stderr_queue))
        stderr_thread.daemon = True
        stderr_thread.start()

        start_time = time.time()
        timed_out = False

        # Store all stdout lines for post-processing
        all_stdout_lines = []

        while True:
            # Check stdout queue
            try:
                line = stdout_queue.get_nowait()
                line = line.strip()
                if line:
                    print(f"[DEBUG][stdout] {line}")
                    all_stdout_lines.append(line)

                    # Try to extract events from JSON messages
                    if "'type': 'send'" in line and "'type': 'api_call'" in line:
                        try:
                            # Find payload part
                            payload_start = line.find("'payload':")
                            if payload_start > 0:
                                # Extract and convert the payload part to JSON
                                payload_str = line[payload_start:].split("}", 1)[0] + "}"
                                payload_str = payload_str.replace("'payload': ", "")
                                payload_str = payload_str.replace("'", '"')
                                payload_str = payload_str.replace("None", "null")
                                payload_str = payload_str.replace("True", "true")
                                payload_str = payload_str.replace("False", "false")

                                try:
                                    payload = json.loads(payload_str)
                                    if isinstance(payload, dict) and payload.get("type") == "api_call":
                                        events.append(payload)
                                        print(f"[+] Captured event: {payload.get('api', 'unknown')}")
                                except json.JSONDecodeError:
                                    pass
                        except Exception as e:
                            print(f"[!] Error processing message: {e}")

            except Empty:
                pass

            # Check stderr queue
            try:
                line = stderr_queue.get_nowait()
                line = line.strip()
                if line:
                    print(f"[DEBUG][stderr] {line}")
            except Empty:
                pass

            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                print(f"[+] Timeout reached ({timeout}s)")
                timed_out = True
                break

            # Check if process has exited
            if proc.poll() is not None:
                print(f"[DEBUG] Process exited with code {proc.returncode}")
                break

            # Avoid busy waiting
            time.sleep(0.1)

        # Cleanup
        if not timed_out and proc.poll() is None:
            print("[DEBUG] Terminating process...")
            proc.terminate()
            time.sleep(0.5)
            if proc.poll() is None:
                print("[DEBUG] Killing process...")
                proc.kill()

        # If we didn't capture any events through the real-time processing,
        # try to extract them from the collected output
        if len(events) == 0:
            print("[!] No events captured during execution. Trying post-processing...")

            # Save raw logs for debugging
            with open(f"{output_path}.raw.log", "w") as f:
                f.write("\n".join(all_stdout_lines))
            print(f"[+] Raw output saved to {output_path}.raw.log")

            # Try to extract events directly from logs
            events.extend(extract_api_events(all_stdout_lines))

            # Look for specific SMS-related patterns
            sms_events = detect_sms_operations(all_stdout_lines)
            events.extend(sms_events)

            print(f"[+] Post-processing extracted {len(events)} events")

        # Save results
        result = {"events": events}
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] Saved {len(events)} events to {output_path}")
        return True

    except KeyboardInterrupt:
        print("\n[!] User interrupted. Stopping...")
        if proc and proc.poll() is None:
            proc.terminate()
        if events:
            with open(output_path, "w") as f:
                json.dump({"events": events}, f, indent=2)
            print(f"[+] Saved {len(events)} partial events to {output_path}")
        return True

    except Exception as e:
        print(f"[!] Critical error: {str(e)}")
        traceback.print_exc()
        return False


def add_sample_metadata(output_path: str, package_name: str) -> bool:
    """
    Add sample metadata to the JSON file for better CAPA integration

    Args:
        output_path: Path to the JSON file
        package_name: Android package name

    Returns:
        bool: True if successful
    """
    try:
        with open(output_path, "r") as f:
            data = json.load(f)

        # Add sample metadata
        data["sample"] = {
            "name": package_name,
            "sha256": "",  # We don't have this for APKs usually
            "md5": "",
            "sha1": ""
        }

        # Add format metadata
        data["metadata"] = {
            "format": "frida",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        return True
    except Exception as e:
        print(f"[-] Error adding metadata: {e}")
        import traceback
        print(f"[DEBUG] {traceback.format_exc()}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Create CAPA-compatible Frida logs from Android apps")
    parser.add_argument("-p", "--package", help="Application package name or search term")
    parser.add_argument("-d", "--device", help="Target specific device ID")
    parser.add_argument("-o", "--output", default="frida_capa.json", help="Output JSON file path")
    parser.add_argument("-s", "--script", default="frida_android_hooks.js", help="Path to Frida hook script")
    parser.add_argument("-t", "--timeout", type=int, default=60, help="How long to run Frida (seconds)")
    args = parser.parse_args()

    print("[DEBUG] Script started with arguments:", args)

    # Check Frida setup
    if not setup_frida(args.device):
        sys.exit(1)

    # Get package name
    if not args.package:
        args.package = input("Enter application package name or search term: ")

    # Skip package search if the argument is already a full package name
    if args.package.count('.') >= 2 and not args.package.startswith('package:'):
        package_name = args.package
        print(f"[+] Using provided package name: {package_name}")
    else:
        # Strip "package:" prefix if present
        search_term = args.package
        if search_term.startswith('package:'):
            search_term = search_term[9:]  # Remove 'package:' prefix
            print(f"[DEBUG] Removed 'package:' prefix, searching for: {search_term}")

        package_name = get_package_name(search_term, args.device)

    if not package_name:
        # As a fallback, if we're dealing with DIVA, try the known package name
        if 'diva' in args.package.lower():
            package_name = 'jakhar.aseem.diva'
            print(f"[DEBUG] Using hardcoded DIVA package name: {package_name}")
        else:
            print("[-] Could not determine package name. Exiting.")
            sys.exit(1)

    print(f"[+] Target package: {package_name}")

    # Check if script exists
    script_path = Path(args.script)
    if not script_path.exists():
        print(f"[-] Script file {script_path} not found")
        sys.exit(1)

    print(f"[+] Using Frida script: {script_path}")

    # Run Frida
    success = run_frida(package_name, str(script_path), args.output, args.device, args.timeout)
    if not success:
        sys.exit(1)

    # Add metadata
    add_sample_metadata(args.output, package_name)

    print(f"[+] Done! You can now analyze with: capa {args.output}")


if __name__ == "__main__":
    main()