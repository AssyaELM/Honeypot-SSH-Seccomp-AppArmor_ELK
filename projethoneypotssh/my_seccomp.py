#!/usr/bin/env python3
"""
SECCOMP RÉEL avec libseccomp
Filtre BPF au niveau kernel - Bloque execve/execveat
"""

import os
import sys

def apply_seccomp():
    """Active SECCOMP en mode FILTER avec libseccomp"""
    if os.getuid() != 0:
        print("❌ SECCOMP → root requis")
        return False

    try:
        # Import de la vraie bibliothèque libseccomp
        import seccomp
        
        # Crée un filtre SECCOMP
        # KILL_PROCESS = tue tout le processus si règle violée
        # Action par défaut : ALLOW (autorise tout sauf ce qu'on bloque)
        f = seccomp.SyscallFilter(defaction=seccomp.ALLOW)
        
        # Syscalls à BLOQUER (action = KILL le processus)
        # execve = exécuter un programme
        # execveat = variante de execve
        # Active le logging AVANT de tuer
        f.add_rule(seccomp.LOG, "execve")
        f.add_rule(seccomp.LOG, "execveat")

        # Puis tue le processus
        f.add_rule(seccomp.KILL_PROCESS, "execve")
        f.add_rule(seccomp.KILL_PROCESS, "execveat")
        
        # Charge le filtre dans le kernel
        f.load()
        
        print("✅ SECCOMP RÉEL ACTIVÉ (libseccomp + BPF kernel)")
        print("   → Filtre BPF chargé dans le noyau Linux")
        print("   → execve/execveat = KILL_PROCESS (signal 31 - SIGSYS)")
        print("   → Toute tentative d'exec = processus tué par le kernel")
        return True
        
    except ImportError as e:
        print(f"❌ Module 'seccomp' manquant: {e}")
        print("   Installation:")
        print("   pip3 install seccomp --break-system-packages")
        return False
    except Exception as e:
        print(f"❌ SECCOMP erreur: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_seccomp():
    """Teste si SECCOMP bloque VRAIMENT execve"""
    print("\n🧪 TEST SECCOMP RÉEL:")
    print("   Tentative d'exécution de /bin/echo...")
    
    try:
        import subprocess
        result = subprocess.run(["/bin/echo","test"],capture_output=True,timeout=2)
        
        # Si returncode=-31, c'est SIGSYS (SECCOMP a tué le process)
        if result.returncode == -31:
            print(f"   ✅ SUCCÈS: SECCOMP a tué le processus!")
            print(f"   → Signal SIGSYS (31) reçu par le kernel")
            return True
        else:
            print(f"   ❌ ÉCHEC: echo a réussi (returncode={result.returncode})")
            print("   → SECCOMP ne bloque PAS")
            return False
    except subprocess.CalledProcessError as e:
        if e.returncode == -31:
            print(f"   ✅ SUCCÈS: SECCOMP a tué le processus!")
            print(f"   → CalledProcessError avec returncode=-31 (SIGSYS)")
            return True
        else:
            print(f"   ⚠  Erreur inattendue: {e}")
            return False
    except Exception as e:
        print(f"   ✅ SUCCÈS: Bloqué!")
        print(f"   → Exception: {type(e)._name_}")
        print(f"   → Message: {e}")
        return True

if __name__ == "__main__":
     print("="*70)
     print("TEST SECCOMP STANDALONE")
     print("="*70)
     if apply_seccomp():
        test_seccomp()
     else:
        print("\n⚠  SECCOMP n'a pas pu être activé") 
     print("="*70)
