#!/usr/bin/env python3
import argparse
import paramiko
import socket
import threading
import re
from queue import Queue
from time import time, strftime

# ANSI color codes
COLOR_GREEN = '\033[92m'
COLOR_RED = '\033[91m'
COLOR_YELLOW = '\033[93m'
COLOR_BLUE = '\033[94m'
COLOR_CYAN = '\033[96m'
COLOR_RESET = '\033[0m'

# IPv4 regex pattern
IPV4_PATTERN = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'

class ResultLogger:
    def __init__(self, log_file=None):
        self.log_file = log_file
        
    def log(self, message, show=True, color=None):
        """Log message to file and optionally to console"""
        timestamp = strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(log_entry)
                
        if show:
            if color:
                print(f"{color}{message}{COLOR_RESET}")
            else:
                print(message)

def extract_ips_from_file(filename):
    """Extract all IPv4 addresses from a file"""
    ips = set()
    try:
        with open(filename, 'r') as f:
            for line in f:
                matches = re.findall(IPV4_PATTERN, line)
                ips.update(matches)
        return sorted(ips)
    except Exception as e:
        print(f"{COLOR_RED}File read error: {e}{COLOR_RESET}")
        return []

def ssh_command(ip, username, password, commands, timeout, logger):
    """Execute SSH commands on an IP"""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect with timeout
        client.connect(ip, username=username, password=password, 
                     timeout=timeout, banner_timeout=timeout)
        
        logger.log(f"[+] Connected to {ip}", color=COLOR_GREEN)
        
        # Execute each command
        for cmd in commands:
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()
                
                # Log command execution
                logger.log(f"[Command] {ip} >>> {cmd}", show=False)
                logger.log(f"[*] {ip} >>> {cmd}", color=COLOR_CYAN)
                
                # Log output
                if output:
                    logger.log(f"[Output] {output}", show=False)
                    logger.log(output)
                
                # Log errors
                if error:
                    logger.log(f"[Error] {error}", show=False)
                    logger.log(f"[!] Error: {error}", color=COLOR_YELLOW)
                    
            except Exception as cmd_error:
                error_msg = f"Command error '{cmd}' on {ip}: {cmd_error}"
                logger.log(f"[Error] {error_msg}", show=False)
                logger.log(f"[!] {error_msg}", color=COLOR_YELLOW)
                
        client.close()
        return True
        
    except paramiko.AuthenticationException:
        error_msg = f"Auth failed on {ip}"
        logger.log(f"[Error] {error_msg}", show=False)
        logger.log(f"[-] {error_msg}", color=COLOR_RED)
    except socket.timeout:
        error_msg = f"Timeout on {ip}"
        logger.log(f"[Error] {error_msg}", show=False)
        logger.log(f"[!] {error_msg}", color=COLOR_YELLOW)
    except Exception as e:
        error_msg = f"Connection error to {ip}: {e}"
        logger.log(f"[Error] {error_msg}", show=False)
        logger.log(f"[-] {error_msg}", color=COLOR_RED)
    return False

def worker(q, username, password, commands, timeout, logger):
    """Thread worker to process IPs"""
    while not q.empty():
        ip = q.get()
        ssh_command(ip, username, password, commands, timeout, logger)
        q.task_done()

def main():
    parser = argparse.ArgumentParser(description="Execute SSH commands on IP list")
    parser.add_argument("-ip", "--ip-file", required=True, help="File containing IPs or text with IPs")
    parser.add_argument("-u", "--username", required=True, help="SSH username")
    parser.add_argument("-p", "--password", required=True, help="SSH password")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-c", "--commands", required=True, 
                      help="Commands to execute (separated by semicolons)")
    parser.add_argument("-to", "--timeout", type=int, default=5, 
                      help="Connection timeout in seconds (default: 5)")
    parser.add_argument("-o", "--output", required=True, help="Log file to save all results")
    
    args = parser.parse_args()

    # Initialize logger
    logger = ResultLogger(args.output)
    
    # Extract IPs from file
    ips = extract_ips_from_file(args.ip_file)
    
    if not ips:
        logger.log("No valid IPv4 found in file", color=COLOR_RED)
        return

    # Prepare commands
    commands = [cmd.strip() for cmd in args.commands.split(';') if cmd.strip()]
    if not commands:
        logger.log("No valid commands specified", color=COLOR_RED)
        return

    logger.log("\n=== Starting scan ===", color=COLOR_BLUE)
    logger.log(f"Threads: {args.threads}")
    logger.log(f"IPs found: {len(ips)}")
    logger.log(f"Timeout: {args.timeout}s")
    logger.log(f"Commands: {' | '.join(commands)}")
    logger.log(f"Log file: {args.output}")
    logger.log("====================", color=COLOR_BLUE)

    # Queue for IPs
    q = Queue()
    for ip in ips:
        q.put(ip)

    # Start threads
    start_time = time()
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, args.username, args.password, commands, args.timeout, logger))
        t.start()
        threads.append(t)

    # Wait for threads to complete
    q.join()
    for t in threads:
        t.join()

    logger.log(f"\n=== Scan completed in {time() - start_time:.2f} seconds ===", color=COLOR_GREEN)

if __name__ == "__main__":
    main()