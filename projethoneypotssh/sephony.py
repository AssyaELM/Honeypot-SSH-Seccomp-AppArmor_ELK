#!/usr/bin/env python3
"""
HONEYPOT SSH + APPARMOR + SECCOMP
→ Tests RÉELS des blocages AppArmor
→ SECCOMP avec libseccomp 
→ Logs détaillés des tentatives
→ Détection brute-force: 5 tentatives/minute
"""

import socket
import threading
import paramiko
import logging
import time
import json
import os
import requests
import subprocess
from datetime import datetime, timezone
from collections import defaultdict


from config import CONFIG
from my_seccomp import apply_seccomp 
#CONFIG TELEGRAM 
TELEGRAM_TOKEN   = "************"  
TELEGRAM_CHAT_ID = "*********************"                                      

# Configuration
HONEYPOT_HOST = '0.0.0.0'
HONEYPOT_PORT = 2222
LOG_FILE = '/var/log/honeypot/ssh_honeypot.json'
WEBHOOK_URL = os.getenv('WEBHOOK_URL', '')

#INITIALISATION 
os.makedirs(CONFIG['log_dir'], exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(CONFIG['log_dir'], 'honeypot.log')),
        logging.StreamHandler()
    ]
)

#FONCTION LOG JSON
def log_to_json(event_type, data):
    """Écrit dans le fichier JSON pour ELK"""
    log_entry = {
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'event_type': event_type,
        **data
    }
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        logging.error(f"Erreur écriture JSON: {e}")


#BRUTE-FORCE + TELEGRAM
class BruteForceDetector:
    def __init__(self):
        self.attempts = defaultdict(list)
        self.lock = threading.Lock()
        self.alerted = set()          

    def record(self, ip, username, password):
        now = time.time()
        with self.lock:
            # garde seulement les 60 dernières secondes
            self.attempts[ip] = [t for t in self.attempts[ip] if now - t < 60]
            self.attempts[ip].append(now)

            count = len(self.attempts[ip])
            if count >= 5 and ip not in self.alerted:
                self.alerted.add(ip)
                threading.Timer(600, lambda: self.alerted.discard(ip)).start()
                logging.warning(f"BRUTE-FORCE → {ip} | {count} tentatives | {username}:{password}")
                self.send_telegram(ip, username, password, count)

    def send_telegram(self, ip, username, password, count):
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        text = f""" 🚨BRUTE-FORCE DÉTECTÉ

IP: {ip}
User: {username}
Pass: {password}
Tentatives: {count}+ en moins de 60s
{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
Honeypot actif"""

        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "Markdown"
        }
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                logging.info(f"ALERTE TELEGRAM ENVOYÉE → {ip}")
            else:
                logging.error(f"Telegram error: {r.text}")
        except Exception as e:
            logging.error(f"Telegram failed: {e}")
brute = BruteForceDetector()


class ESLogger:
    def __init__(self):
        self.enabled = False
        try:
            r = requests.get(CONFIG['elasticsearch_url'], timeout=2)
            self.enabled = r.status_code == 200
        except: pass
    
    def log(self, typ, data):
        if not self.enabled: return
        try:
            doc = {"@timestamp": datetime.now().isoformat(), "event_type": typ, **data}
            requests.post(f"{CONFIG['elasticsearch_url']}/{CONFIG['elasticsearch_index']}/_doc", json=doc, timeout=2)
        except: pass

es = ESLogger()

#COMMANDES DANGEREUSES
DANGEROUS = ["wget", "curl", "nc", "ncat", "netcat", "python", "python3", "perl", "php", "sh", "bash", "rm", "dd"]

#TEST APPARMOR RÉEL
def test_apparmor_real(channel, ip):
    """Teste VRAIMENT les blocages AppArmor"""
    channel.send(b"\r\nTEST APPARMOR REEL\r\n")
    
    tests = [
        ("/etc/passwd", "read", "Lecture /etc/passwd"),
        ("/etc/shadow", "read", "Lecture /etc/shadow"),
        ("/etc/ssh/sshd_config", "read", "Lecture config SSH"),
        ("/usr/bin/wget", "exec", "Execution wget"),
        ("/usr/bin/curl", "exec", "Execution curl"),
        ("/bin/bash", "exec", "Execution bash"),
    ]
    
    blocked = 0
    allowed = 0
    
    for path, action, desc in tests:
        try:
            if action == "read":
                with open(path, 'r') as f:
                    content = f.read(10)
                channel.send(f"[FAIL] {desc} - AUTORISE! AppArmor ne bloque pas!\r\n".encode())
                logging.error(f"APPARMOR FAIL → {ip} | {desc} - ACCESSIBLE!")
                allowed += 1
            elif action == "exec":
                result = subprocess.run([path, "--version"], capture_output=True, timeout=1, text=True)
                channel.send(f"[FAIL] {desc} - EXECUTABLE! AppArmor ne bloque pas!\r\n".encode())
                logging.error(f"APPARMOR FAIL → {ip} | {desc} - EXECUTABLE!")
                allowed += 1
        except PermissionError as e:
            channel.send(f"[OK] {desc} - BLOQUE par AppArmor!\r\n".encode())
            logging.info(f"APPARMOR OK → {ip} | {desc} - BLOQUE (PermissionError)")
            blocked += 1
        except FileNotFoundError as e:
            channel.send(f"[OK] {desc} - Fichier inexistant (normal)\r\n".encode())
            logging.info(f"APPARMOR OK → {ip} | {desc} - FileNotFound")
            blocked += 1
        except subprocess.TimeoutExpired:
            channel.send(f"[PARTIAL] {desc} - Timeout (peut-etre bloque)\r\n".encode())
            logging.warning(f"APPARMOR TIMEOUT → {ip} | {desc}")
            blocked += 1
        except Exception as e:
            channel.send(f"[OK] {desc} - Erreur: {type(e).__name__}\r\n".encode())
            logging.info(f"APPARMOR OK → {ip} | {desc} - BLOQUE ({type(e).__name__})")
            blocked += 1
    
    channel.send(f"\r\nResultat: {blocked} bloques, {allowed} autorises\r\n".encode())
    channel.send(b"=== FIN TEST ===\r\n\r\n")
    
    if allowed > 0:
        logging.error(f"ALERTE SECURITE → {ip} | AppArmor a laisse passer {allowed} tests!")
    else:
        logging.info(f"SECURITE OK → {ip} | Tous les tests bloques par AppArmor")

#TEST SECCOMP RÉEL
def test_seccomp_real(channel, ip):
    """Teste les blocages SECCOMP"""
    channel.send(b"\r\n=== TEST SECCOMP REEL ===\r\n")
    
    tests = [
        ("/bin/echo", "Test echo"),
        ("/usr/bin/wget", "Test wget"),
        ("/bin/bash", "Test bash"),
    ]
    
    blocked = 0
    allowed = 0
    
    for cmd, desc in tests:
        try:
            result = subprocess.run([cmd, "--version"], 
                                   capture_output=True, 
                                   timeout=1)
            channel.send(f"[FAIL] {desc} - EXECUTABLE! SECCOMP ne bloque pas!\r\n".encode())
            logging.error(f"SECCOMP FAIL → {ip} | {desc} - EXECUTABLE!")
            allowed += 1
        except FileNotFoundError:
            channel.send(f"[INFO] {desc} - Fichier inexistant\r\n".encode())
            blocked += 1
        except subprocess.CalledProcessError as e:
            if e.returncode == -31:
                channel.send(f"[OK] {desc} - BLOQUE par SECCOMP (SIGSYS)!\r\n".encode())
                logging.info(f"SECCOMP OK → {ip} | {desc} - BLOQUE (SIGSYS)")
                blocked += 1
            else:
                channel.send(f"[PARTIAL] {desc} - Erreur code {e.returncode}\r\n".encode())
                blocked += 1
        except Exception as e:
            channel.send(f"[OK] {desc} - BLOQUE: {type(e).__name__}\r\n".encode())
            logging.info(f"SECCOMP OK → {ip} | {desc} - BLOQUE ({type(e).__name__})")
            blocked += 1
    
    channel.send(f"\r\nResultat: {blocked} bloques, {allowed} autorises\r\n".encode())
    channel.send(b"=== FIN TEST ===\r\n\r\n")

#TENTATIVE RÉELLE D'ACCÈS
def try_real_access(channel, ip, cmd):
    """Tente réellement d'accéder aux fichiers/commandes"""
    c = cmd.strip().lower()
    
    if c.startswith("cat ") or c.startswith("less ") or c.startswith("more ") or c.startswith("head ") or c.startswith("tail "):
        parts = c.split()
        if len(parts) >= 2:
            filepath = parts[1]
            try:
                with open(filepath, 'r') as f:
                    content = f.read(100)
                channel.send(b"\r\n[FAIL] Fichier accessible!\r\n")
                channel.send(content[:50].encode() + b"...\r\n")
                logging.error(f"APPARMOR FAIL → {ip} | Acces autorise: {filepath}")
            except PermissionError:
                channel.send(b"\r\n[BLOQUE] AppArmor a bloque l'acces!\r\n")
                logging.info(f"APPARMOR OK → {ip} | Acces bloque: {filepath}")
            except FileNotFoundError:
                channel.send(f"\r\ncat: {filepath}: No such file or directory\r\n".encode())
            except Exception as e:
                channel.send(f"\r\n[BLOQUE] Erreur: {type(e).__name__}\r\n".encode())
                logging.info(f"APPARMOR OK → {ip} | Bloque: {filepath} ({type(e).__name__})")
            return True
    
    dangerous_cmds = {
        "wget": "/usr/bin/wget",
        "curl": "/usr/bin/curl",
        "nc": "/bin/nc",
        "bash": "/bin/bash",
        "sh": "/bin/sh",
        "python": "/usr/bin/python3",
        "python3": "/usr/bin/python3",
    }
    
    for cmd_name, cmd_path in dangerous_cmds.items():
        if cmd_name in c:
            channel.send(f"\r\n[ALERTE] Tentative d'execution: {cmd_name}\r\n".encode())
            logging.warning(f"DANGEROUS CMD → {ip} | {cmd}")
            try:
                result = subprocess.run([cmd_path, "--version"], 
                                       capture_output=True, 
                                       timeout=2, 
                                       text=True)
                
                if result.returncode == -31:
                    channel.send(b"[BLOQUE] SECCOMP a tue le processus (SIGSYS)!\r\n")
                    logging.info(f"SECCOMP OK → {ip} | {cmd_name} TUE PAR SECCOMP")
                elif result.returncode == 0:
                    channel.send(b"[FAIL] Commande executable! SECCOMP ne bloque pas!\r\n")
                    logging.error(f"SECCOMP FAIL → {ip} | {cmd_name} EXECUTABLE!")
                else:
                    channel.send(f"[BLOQUE] Erreur code {result.returncode}\r\n".encode())
                    logging.info(f"SECCOMP OK → {ip} | {cmd_name} BLOQUE (code {result.returncode})")
            except subprocess.CalledProcessError as e:
                if e.returncode == -31:
                    channel.send(b"[BLOQUE] SECCOMP a tue le processus (SIGSYS)!\r\n")
                    logging.info(f"SECCOMP OK → {ip} | {cmd_name} TUE PAR SECCOMP")
                else:
                    channel.send(f"[BLOQUE] Erreur code {e.returncode}\r\n".encode())
            except PermissionError:
                channel.send(b"[BLOQUE] AppArmor a bloque l'execution!\r\n")
                logging.info(f"APPARMOR OK → {ip} | {cmd_name} BLOQUE")
            except FileNotFoundError:
                channel.send(b"[BLOQUE] Commande inexistante\r\n")
            except subprocess.TimeoutExpired:
                channel.send(b"[BLOQUE] Timeout (probablement bloque)\r\n")
                logging.info(f"SECCOMP OK → {ip} | {cmd_name} TIMEOUT")
            except Exception as e:
                channel.send(f"[BLOQUE] Erreur: {type(e).__name__}\r\n".encode())
                logging.info(f"SECCOMP OK → {ip} | {cmd_name} BLOQUE ({type(e).__name__})")
            return True
    
    return False

#SIMULATION
def simulate(channel, ip, cmd):
    """Simule les commandes normales, teste réellement les dangereuses"""
    c = cmd.strip().lower()
    
    if c == "test-apparmor":
        test_apparmor_real(channel, ip)
        return
    
    if c == "test-seccomp":
        test_seccomp_real(channel, ip)
        return
    
    if c == "test-all":
        test_apparmor_real(channel, ip)
        test_seccomp_real(channel, ip)
        return
    
    if try_real_access(channel, ip, cmd):
        return
    
    if c == "whoami": 
        channel.send(b"\r\nroot\r\n")
    elif c == "id": 
        channel.send(b"\r\nuid=0(root) gid=0(root) groups=0(root)\r\n")
    elif c == "pwd": 
        channel.send(b"\r\n/root\r\n")
    elif c.startswith("ls"): 
        channel.send(b"\r\nbin  boot  dev  etc  home  lib  opt  root  tmp  usr  var\r\n")
    elif c == "uname -a": 
        channel.send(b"\r\nLinux server 5.4.0 x86_64 GNU/Linux\r\n")
    elif c.startswith("echo "): 
        channel.send(f"\r\n{c[5:]}\r\n".encode())
    elif c == "clear": 
        channel.send(b"\r\n" * 50)
    elif c == "help":
        channel.send(b"\r\nCommandes disponibles:\r\n")
        channel.send(b"  test-apparmor  - Teste les blocages AppArmor\r\n")
        channel.send(b"  test-seccomp   - Teste les blocages SECCOMP\r\n")
        channel.send(b"  test-all       - Teste tout\r\n")
        channel.send(b"  whoami, id, pwd, ls, uname, cat, wget, curl, etc.\r\n")
    else:
        channel.send(f"\r\nbash: {cmd}: command not found\r\n".encode())

#HANDLER
class Handler(paramiko.ServerInterface):
    def __init__(self, ip): 
        self.ip = ip
        self.username = None
        self.event = threading.Event()
    
    def check_auth_password(self, u, p):
        self.username = u
        logging.warning(f" Auth - IP: {self.ip} | User: {u} | Pass: {p}")
        
        log_to_json('ssh_login_attempt', {
            'source_ip': self.ip,
            'username': u,
            'password': p,
            'auth_type': 'password',
            'success': False
        })
        
        brute.record(self.ip, u, p)
        es.log('auth', {'ip': self.ip, 'user': u, 'pass': p})
        
        self.event.set()
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, u): 
        return "password"
    
    def check_channel_request(self, k, c): 
        return paramiko.OPEN_SUCCEEDED if k == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, c): 
        return True
    
    def check_channel_pty_request(self, *a): 
        return True

#CLIENT
def client(c, a, key):
    ip = a[0]
    logging.info(f"➡️  Connexion: {ip}")
    
    t = None
    try:
        t = paramiko.Transport(c)
        t.add_server_key(key)
        
        handler = Handler(ip)
        t.start_server(server=handler)
        
        ch = t.accept(20)
        if not ch: 
            return
        
        ch.send(b"Ubuntu 20.04.5 LTS\r\n")
        ch.send(b"Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y").encode() + b"\r\n\r\n")
        ch.send(b"root@server:~# ")
        
        buf = ""
        while True:
            if ch.recv_ready():
                data = ch.recv(1024).decode('utf-8', 'ignore')
                for x in data:
                    if x in '\r\n':
                        if buf.strip():
                            logging.info(f"💻 Shell - {ip} | {buf.strip()}")
                            
                            log_to_json('ssh_command', {
                                'source_ip': ip,
                                'username': handler.username or 'unknown',
                                'command': buf.strip()
                            })
                            
                            es.log('cmd', {'ip': ip, 'cmd': buf.strip()})
                            simulate(ch, ip, buf.strip())
                        buf = ""
                        ch.send(b"\r\nroot@server:~# ")
                    elif x == '\x7f' and buf:
                        buf = buf[:-1]
                        ch.send(b'\b \b')
                    else:
                        buf += x
                        ch.send(x.encode())
            time.sleep(0.1)
            
    except paramiko.ssh_exception.SSHException as e:
        logging.warning(f"  SSHException de {ip}: {e}")
    except Exception as e:
        logging.debug(f"Erreur client {ip}: {e}")
    finally:
        logging.info(f"⬅️  Déconnexion: {ip}")
        try:
            if t:
                t.close()
            c.close()
        except:
            pass

#MAIN
def main():
    key_file = os.path.join(CONFIG['log_dir'], 'honeypot_rsa_key')
    if os.path.exists(key_file):
        logging.info(" Chargement clé hôte existante")
        key = paramiko.RSAKey(filename=key_file)
    else:
        logging.info(" Génération nouvelle clé hôte")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_file)
    
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((CONFIG['host'], CONFIG['port']))
    s.listen(100)
    
    logging.info(f"🍯 Honeypot SSH démarré sur {CONFIG['host']}:{CONFIG['port']}")
    logging.info(f"📁 Logs dans: {CONFIG['log_dir']}")
    logging.info(f"📝 JSON: {LOG_FILE}")
    logging.info(f"🚨 Seuil brute-force: 5 tentatives/60s (= 1 minute)")
    
    print("=" * 70)
    print("HONEYPOT SSH ACTIF")
    print("AppArmor: Tests REELS des blocages")
    print("Détection brute-force: 5 tentatives par minute")
    print("-" * 70)
    
    if apply_seccomp():
        print(" SECCOMP: execve = KILL (RÉEL - kernel BPF)")
        logging.info(" SECCOMP activé")
    else:
        print("  SECCOMP: désactivé (continuez sans)")
        logging.warning("  SECCOMP désactivé")
    
    print("-" * 70)
    print("Commandes de test:")
    print("  test-apparmor  - Teste AppArmor")
    print("  test-seccomp   - Teste SECCOMP")
    print("  test-all       - Teste tout")
    print("=" * 70)
    print(" Écoute sur {}:{}".format(CONFIG['host'], CONFIG['port']))
    print("Appuyez sur Ctrl+C pour arrêter")
    print("=" * 70)
    
    try:
        while True:
            c, a = s.accept()
            t = threading.Thread(target=client, args=(c, a, key))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        logging.info("\n🛑 Arrêt du honeypot")
    finally:
        s.close()

if __name__ == '__main__':
    main()
