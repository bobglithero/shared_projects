#!/usr/bin/env python3
"""Monitor and display attack progress for educational purposes"""

import time
from datetime import datetime
from pathlib import Path

def monitor_logs():
    """Monitor various log files and display attack progress"""
    
    log_files = {
        "MCP Interactions": "/demo/logs/master_mcp.log",
        "Intelligence Processing": "/demo/logs/intelligence_mcp.log", 
        "Decoded Instructions": "/demo/logs/decoded_instructions.log",
        "Data Exfiltration": "/demo/logs/demo_exfiltration.log",
        "Captured Data": "/demo/logs/captured_exfiltration.log"
    }
    
    print("🔍 MCP Security Attack Monitor")
    print("=" * 50)
    print("Monitoring for educational security demonstrations...")
    print("Press Ctrl+C to stop monitoring\n")
    
    # Track last positions in files
    positions = {}
    for name, filepath in log_files.items():
        positions[name] = 0
    
    try:
        while True:
            activity_detected = False
            
            for name, filepath in log_files.items():
                if Path(filepath).exists():
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            f.seek(positions[name])
                            new_content = f.read()
                            if new_content.strip():
                                print(f"\n🚨 [{datetime.now().strftime('%H:%M:%S')}] {name}:")
                                print("-" * 30)
                                print(new_content.strip())
                                activity_detected = True
                            positions[name] = f.tell()
                    except (IOError, OSError, UnicodeDecodeError) as e:
                        print(f"Warning: Could not read {filepath}: {e}")
                        continue
            
            if activity_detected:
                print("\n" + "=" * 50)
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\n✅ Monitoring stopped.")
        print("📊 Check /demo/logs/ for complete attack demonstration logs.")

if __name__ == "__main__":
    monitor_logs()
