#!/usr/bin/env python3
"""
Vulnerable FTP Server - CVE benzeri zafiyetler:
- Anonymous login
- Plaintext credentials
- PORT komutuna izin (FTP bounce attack)
GNU inetutils ftpd 1.9 taklidi (zafiyetli versiyon)
"""

import socket
import threading
import os
import sys

FTP_ROOT = "/tmp/ftproot"
USER_DB = {
    b"anonymous": b"",      # boş şifre
    b"anonymous": b"anonymous",
    b"admin": b"admin",
    b"ftp": b"ftp",
}

class FTPHandler(threading.Thread):
    def __init__(self, client_sock, addr):
        super().__init__()
        self.client = client_sock
        self.addr = addr
        self.authenticated = False
        self.user = None
        self.current_dir = FTP_ROOT
        self.data_sock = None
        self.data_listen_sock = None   # PASV için
        self.data_port = None           # PORT için (ip,port)
        self.running = True

    def send_response(self, code, message):
        resp = f"{code} {message}\r\n"
        self.client.send(resp.encode())

    def run(self):
        self.send_response(220, "GNU inetutils ftpd 1.9 (Debian) ready")
        buffer = b""
        while self.running:
            try:
                data = self.client.recv(1024)
                if not data:
                    break
                buffer += data
                if b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    line = line.rstrip(b'\r')
                    self.handle_command(line)
            except Exception as e:
                print(f"Hata: {e}")
                break
        self.client.close()

    def handle_command(self, cmd_line):
        cmd = cmd_line.split(b' ')[0].upper()
        args = cmd_line[len(cmd)+1:] if len(cmd_line) > len(cmd) else b''

        if cmd == b'USER':
            self.user = args
            self.send_response(331, f"User {args.decode()} ok, need password")
        elif cmd == b'PASS':
            if not self.user:
                self.send_response(503, "Login with USER first")
                return
            # Anonymous login kontrolü
            if self.user == b'anonymous' and (args == b'' or args == b'anonymous'):
                self.authenticated = True
                self.send_response(230, "Anonymous access granted")
            elif (self.user, args) in USER_DB.items():
                self.authenticated = True
                self.send_response(230, "User logged in")
            else:
                self.send_response(530, "Login incorrect")
        elif cmd == b'PWD':
            if not self.authenticated:
                self.send_response(530, "Not logged in")
            else:
                path = self.current_dir.replace(FTP_ROOT, "")
                if not path:
                    path = "/"
                self.send_response(257, f"\"{path}\" is current directory")
        elif cmd == b'CWD':
            if not self.authenticated:
                self.send_response(530, "Not logged in")
            else:
                new_path = os.path.join(self.current_dir, args.decode())
                if os.path.isdir(new_path):
                    self.current_dir = new_path
                    self.send_response(250, "Directory changed")
                else:
                    self.send_response(550, "Directory not found")
        elif cmd == b'TYPE':
            # Sadece ASCII veya BINARY, gerçek işlem yapmıyoruz
            self.send_response(200, "Type set to " + args.decode())
        elif cmd == b'PORT':
            # PORT h1,h2,h3,h4,p1,p2
            parts = args.split(b',')
            if len(parts) == 6:
                ip = ".".join(str(p) for p in parts[:4])
                port = int(parts[4]) * 256 + int(parts[5])
                self.data_port = (ip, port)
                self.send_response(200, "PORT command successful")
            else:
                self.send_response(501, "Syntax error in PORT")
        elif cmd == b'PASV':
            # Pasif mod: 0.0.0.0 üzerinde rastgele bir port dinle
            listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listen_sock.bind(('0.0.0.0', 0))
            listen_sock.listen(1)
            ip = self.client.getsockname()[0].replace('.', ',')
            port = listen_sock.getsockname()[1]
            p1 = port // 256
            p2 = port % 256
            self.data_listen_sock = listen_sock
            self.send_response(227, f"Entering Passive Mode ({ip},{p1},{p2})")
        elif cmd == b'LIST':
            if not self.authenticated:
                self.send_response(530, "Not logged in")
                return
            # Data connection aç
            data_conn = self.open_data_connection()
            if data_conn:
                self.send_response(150, "Here comes directory listing")
                # Dizin içeriğini gönder
                try:
                    files = os.listdir(self.current_dir)
                    listing = ""
                    for f in files:
                        listing += f"drwxr-xr-x 1 ftp ftp 0 Jan 1 1970 {f}\r\n"
                    data_conn.send(listing.encode())
                    data_conn.close()
                    self.send_response(226, "Directory listing complete")
                except:
                    self.send_response(550, "Cannot list directory")
            else:
                self.send_response(425, "Cannot open data connection")
        elif cmd == b'RETR':
            if not self.authenticated:
                self.send_response(530, "Not logged in")
                return
            filename = args.decode()
            path = os.path.join(self.current_dir, filename)
            if os.path.isfile(path):
                data_conn = self.open_data_connection()
                if data_conn:
                    self.send_response(150, "Opening data connection")
                    with open(path, 'rb') as f:
                        data_conn.send(f.read())
                    data_conn.close()
                    self.send_response(226, "Transfer complete")
                else:
                    self.send_response(425, "Cannot open data connection")
            else:
                self.send_response(550, "File not found")
        elif cmd == b'STOR':
            if not self.authenticated:
                self.send_response(530, "Not logged in")
                return
            filename = args.decode()
            path = os.path.join(self.current_dir, filename)
            data_conn = self.open_data_connection()
            if data_conn:
                self.send_response(150, "Ready to receive data")
                with open(path, 'wb') as f:
                    while True:
                        chunk = data_conn.recv(4096)
                        if not chunk:
                            break
                        f.write(chunk)
                data_conn.close()
                self.send_response(226, "Transfer complete")
            else:
                self.send_response(425, "Cannot open data connection")
        elif cmd == b'QUIT':
            self.send_response(221, "Goodbye")
            self.running = False
        elif cmd == b'FEAT':
            self.send_response(211, "Features:\n PASV\n PORT\n UTF8\n211 End")
        elif cmd == b'HELP':
            self.send_response(214, "Commands: USER PASS PWD CWD TYPE PORT PASV LIST RETR STOR QUIT FEAT HELP")
        else:
            self.send_response(502, "Command not implemented")

    def open_data_connection(self):
        # Önce PORT ile verilmişse ona bağlan
        if self.data_port:
            ip, port = self.data_port
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((ip, port))
                self.data_port = None
                return s
            except:
                return None
        # Yoksa PASV ile dinleyen varsa onu kullan
        if self.data_listen_sock:
            try:
                conn, _ = self.data_listen_sock.accept()
                self.data_listen_sock.close()
                self.data_listen_sock = None
                return conn
            except:
                return None
        return None

def main():
    host = '0.0.0.0'
    port = 21
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    print(f"[*] FTP Server running on {host}:{port} (Vulnerable)")
    print(f"[*] Root directory: {FTP_ROOT}")
    while True:
        client, addr = server.accept()
        t = FTPHandler(client, addr)
        t.start()

if __name__ == "__main__":
    main()
