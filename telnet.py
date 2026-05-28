#!/usr/bin/env python3
"""
GNU inetutils telnetd 2.6 (Debian) taklidi - CVE-2026-24061
Nmap'in doğru algılaması için optimize edildi.
"""

import socket
import threading
import subprocess
import sys
import os

IAC = b'\xff'
WILL = b'\xfb'
WONT = b'\xfc'
DO   = b'\xfd'
DONT = b'\xfe'
SB   = b'\xfa'
SE   = b'\xf0'

TELOPT_ECHO = 1
TELOPT_SGA = 3
TELOPT_NEW_ENVIRON = 39

USERNAME = b"admin"
PASSWORD = b"admin"

FLAG_CONTENT = "CTF{7eln3t_4uth_bypass_cve_2026_24061}\n"
FLAG_PATH = "/tmp/flag.txt"
try:
    with open(FLAG_PATH, "w") as f:
        f.write(FLAG_CONTENT)
    print(f"[*] Flag yazıldı: {FLAG_PATH}")
except PermissionError:
    FLAG_PATH = "/root/flag.txt"
    with open(FLAG_PATH, "w") as f:
        f.write(FLAG_CONTENT)
    print(f"[*] Flag yazıldı: {FLAG_PATH}")

def handle_client(client_sock, addr):
    print(f"[+] Bağlantı: {addr}")
    try:
        # İlk Telnet opsiyonları: WILL ECHO, WILL SGA
        client_sock.send(IAC + WILL + bytes([TELOPT_ECHO]))
        client_sock.send(IAC + WILL + bytes([TELOPT_SGA]))

        # Banner (sadece sürüm bilgisi)
        banner = b"\r\nGNU inetutils telnetd 2.6 (Debian)\r\n"
        banner += b"Login with admin/admin OR exploit NEW_ENVIRON with USER=-f root\r\n\r\n"
        client_sock.send(banner)

        authenticated = False
        bypass_triggered = False
        username = b""
        password = b""
        buf = b""

        while not authenticated and not bypass_triggered:
            data = client_sock.recv(1024)
            if not data:
                break
            buf += data
            i = 0
            while i < len(buf):
                if buf[i] == IAC[0]:
                    if i+1 >= len(buf):
                        break
                    cmd = buf[i+1]
                    if cmd == DO[0]:
                        if i+2 < len(buf):
                            opt = buf[i+2]
                            if opt == TELOPT_NEW_ENVIRON:
                                client_sock.send(IAC + WILL + bytes([opt]))
                                print("[*] Client NEW_ENVIRON istedi")
                            else:
                                client_sock.send(IAC + WONT + bytes([opt]))
                            i += 3
                        else:
                            break
                    elif cmd == WILL[0]:
                        if i+2 < len(buf):
                            opt = buf[i+2]
                            client_sock.send(IAC + DO + bytes([opt]))
                            i += 3
                        else:
                            break
                    elif cmd == SB[0]:
                        end = buf.find(IAC + SE, i)
                        if end == -1:
                            break
                        sub = buf[i+2:end]
                        if sub and sub[0] == TELOPT_NEW_ENVIRON:
                            sub_str = sub[1:].decode('ascii', errors='ignore')
                            print(f"[*] NEW_ENVIRON içeriği: {sub_str}")
                            if "USER" in sub_str and "-f root" in sub_str:
                                print("[!] AUTH BYPASS tetiklendi!")
                                bypass_triggered = True
                                client_sock.send(b"\r\n[!] Authentication bypassed. Root shell ready.\r\n")
                                client_sock.send(b"# ")
                                command_shell(client_sock, addr)
                                return
                        i = end + 2
                    elif cmd == SE[0]:
                        i += 2
                    else:
                        i += 2
                else:
                    if not authenticated and not bypass_triggered:
                        if username == b"":
                            client_sock.send(b"login: ")
                            if b'\n' in buf[i:]:
                                line, buf = buf.split(b'\n', 1)
                                username = line.strip()
                                i = 0
                            else:
                                break
                        elif password == b"":
                            client_sock.send(b"Password: ")
                            if b'\n' in buf[i:]:
                                line, buf = buf.split(b'\n', 1)
                                password = line.strip()
                                i = 0
                                if username == USERNAME and password == PASSWORD:
                                    authenticated = True
                                    client_sock.send(b"\r\nAccess granted. Welcome.\r\n")
                                    client_sock.send(b"$ ")
                                    command_shell(client_sock, addr)
                                    return
                                else:
                                    client_sock.send(b"\r\nLogin incorrect\r\n")
                                    username = b""
                                    password = b""
                            else:
                                break
                    else:
                        i += 1
        client_sock.close()
    except Exception as e:
        print(f"Hata: {e}")
        client_sock.close()

def command_shell(client_sock, addr):
    try:
        env = os.environ.copy()
        env['PATH'] = '/bin:/usr/bin:/usr/local/bin'
        buffer = b""
        while True:
            data = client_sock.recv(1024)
            if not data:
                break
            buffer += data
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                line = line.rstrip(b'\r')
                cmd = line.decode('utf-8', errors='ignore').strip()
                if cmd == "":
                    continue
                if cmd == "exit":
                    client_sock.send(b"Bye\r\n")
                    return
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, timeout=5, env=env)
                    output = result.stdout + result.stderr
                    if output:
                        client_sock.send(output)
                    else:
                        client_sock.send(b"\r\n")
                except subprocess.TimeoutExpired:
                    client_sock.send(b"Command timed out\r\n")
                except Exception as e:
                    client_sock.send(b"Error: " + str(e).encode() + b"\r\n")
                client_sock.send(b"$ ")
    except:
        pass
    finally:
        client_sock.close()

def main():
    host = '0.0.0.0'
    port = 23
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] Telnet sunucusu {host}:{port} üzerinde çalışıyor (GNU inetutils 2.6)")
    print(f"[*] Flag: {FLAG_PATH}")
    while True:
        client, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client, addr))
        t.start()

if __name__ == "__main__":
    main()
