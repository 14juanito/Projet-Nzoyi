# NZOYI — Guide d'installation du Lab

## Architecture cible

```
PC 1 (16GB) — Kali Linux bare-metal         PC 2 (8GB) — Ubuntu Server bare-metal
🗡️ ATTAQUANT                                🛡️ DÉFENSEUR + CIBLE
─────────────────────────────                ─────────────────────────────
• NZOYI (agents Python)                      • Ubuntu Server 22.04
• Ollama + Mistral 7B                        • Suricata (NIDS)
• Wazuh Manager (optionnel, Docker)          • Services vulnérables intentionnels
• Python 3.11+                               • Wazuh Agent (optionnel)

         eth0: 192.168.100.10                         eth0: 192.168.100.11
              │                                            │
              └──────── câble Ethernet direct ─────────────┘
                    ou switch dédié (réseau isolé)
                    Subnet: 192.168.100.0/24
```

---

## ÉTAPE 1 — Installer Ubuntu Server sur PC 2

### 1.1 Télécharger l'ISO
Depuis le PC 1 (Kali), télécharge sur une clé USB :
```bash
# Télécharger Ubuntu Server 22.04 LTS
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.4-live-server-amd64.iso

# Créer la clé USB bootable (remplace /dev/sdX par ta clé)
sudo dd if=ubuntu-22.04.4-live-server-amd64.iso of=/dev/sdX bs=4M status=progress
```

### 1.2 Installation
- Boot PC 2 sur la clé USB
- Langue : français ou anglais
- **Réseau** : configurer en IP statique pendant l'installation si possible,
  sinon on le fera après
- **Nom utilisateur** : `defender` (ou ce que tu veux)
- **Nom machine** : `nzoyi-target`
- Cocher **OpenSSH Server** quand proposé
- Pas besoin de snaps supplémentaires

### 1.3 Premier boot — mise à jour
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y net-tools curl wget vim htop
```

---

## ÉTAPE 2 — Configurer le réseau isolé

### 2.1 Connexion physique
Connecte les deux PC avec un **câble Ethernet direct** (ou via un switch dédié).
⚠️ Ce réseau doit être **isolé d'Internet** pendant les tests.

### 2.2 Sur PC 2 (Ubuntu Server) — IP statique
```bash
# Identifier l'interface réseau
ip link show
# Note le nom (ex: enp0s3, eth0, ens33...)

# Configurer l'IP statique via Netplan
sudo nano /etc/netplan/00-installer-config.yaml
```

Contenu :
```yaml
network:
  version: 2
  ethernets:
    enp0s3:          # <-- remplace par ton interface
      addresses:
        - 192.168.100.11/24
      routes:
        - to: 192.168.100.0/24
          via: 192.168.100.11
```

```bash
sudo netplan apply
```

### 2.3 Sur PC 1 (Kali) — IP statique
```bash
# Identifier l'interface
ip link show

# Configurer temporairement
sudo ip addr add 192.168.100.10/24 dev eth0  # remplace eth0
sudo ip link set eth0 up

# OU configurer de manière permanente via /etc/network/interfaces
sudo nano /etc/network/interfaces
```

Ajouter :
```
auto eth0
iface eth0 inet static
    address 192.168.100.10
    netmask 255.255.255.0
```

```bash
sudo systemctl restart networking
```

### 2.4 Test de connectivité
```bash
# Depuis Kali (PC 1)
ping 192.168.100.11

# Depuis Ubuntu (PC 2)
ping 192.168.100.10
```

✅ Si les pings passent, le réseau isolé fonctionne.

---

## ÉTAPE 3 — Installer Suricata sur PC 2

### 3.1 Installation
```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata suricata-update
```

### 3.2 Configuration de base
```bash
# Identifier l'interface réseau à surveiller
ip link show
# C'est la même interface que celle configurée en 192.168.100.11

# Configurer Suricata
sudo nano /etc/suricata/suricata.yaml
```

Modifications clés dans `suricata.yaml` :
```yaml
# Chercher HOME_NET et remplacer
vars:
  address-groups:
    HOME_NET: "[192.168.100.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

# Chercher af-packet et configurer l'interface
af-packet:
  - interface: enp0s3      # <-- ton interface
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

# Activer le logging EVE JSON (essentiel pour NZOYI)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            tagged-packets: yes
        - stats:
            totals: yes
```

### 3.3 Mettre à jour les règles de détection
```bash
sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open
sudo suricata-update
```

### 3.4 Démarrer Suricata
```bash
# Test de configuration
sudo suricata -T -c /etc/suricata/suricata.yaml

# Démarrer
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata
```

### 3.5 Vérifier que Suricata fonctionne
```bash
# Surveiller les alertes en temps réel
sudo tail -f /var/log/suricata/eve.json | jq '.event_type'
```

---

## ÉTAPE 4 — Rendre PC 2 intentionnellement vulnérable

⚠️ Ces services sont installés UNIQUEMENT sur le réseau isolé.
Ne JAMAIS exposer cette machine à Internet.

### 4.1 Serveur SSH (déjà installé)
```bash
# Vérifier que SSH tourne
sudo systemctl status ssh

# Le rendre légèrement plus permissif pour les tests
sudo nano /etc/ssh/sshd_config
# Ajouter : PermitRootLogin yes
# Ajouter : PasswordAuthentication yes
sudo systemctl restart ssh
```

### 4.2 Serveur Web Apache
```bash
sudo apt install -y apache2
sudo systemctl enable apache2
sudo systemctl start apache2

# Vérifier
curl http://localhost
```

### 4.3 Serveur FTP
```bash
sudo apt install -y vsftpd
sudo nano /etc/vsftpd.conf
# Mettre : anonymous_enable=YES
sudo systemctl restart vsftpd
```

### 4.4 Créer un utilisateur avec mot de passe faible (pour les tests brute force)
```bash
sudo useradd -m -s /bin/bash testuser
echo "testuser:password123" | sudo chpasswd
```

---

## ÉTAPE 5 — Test de baseline (validation manuelle)

C'est le test le plus important : vérifier que Suricata détecte
un scan Nmap AVANT d'écrire le moindre code agent.

### 5.1 Depuis Kali (PC 1), lancer un scan
```bash
nmap -sV -sC 192.168.100.11
```

### 5.2 Sur PC 2, vérifier les alertes Suricata
```bash
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")' | tail -20
```

✅ Si tu vois des alertes liées au scan Nmap → **le baseline fonctionne**.
C'est exactement ce que NZOYI va ensuite apprendre à contourner.

### 5.3 Documenter le baseline (pour le mémoire)
```bash
# Compter les alertes générées par un scan standard
sudo cat /var/log/suricata/eve.json | jq 'select(.event_type=="alert")' | wc -l

# Sauvegarder ce résultat — c'est ton point de comparaison
# Exemple : "Un scan Nmap -sV standard génère 47 alertes Suricata"
```

---

## ÉTAPE 6 — Installer les outils sur Kali (PC 1)

### 6.1 Python et dépendances NZOYI
```bash
# Kali a déjà Python 3, vérifier la version
python3 --version

# Installer pip si nécessaire
sudo apt install -y python3-pip python3-venv

# Créer un environnement virtuel pour NZOYI
cd ~
python3 -m venv nzoyi-env
source nzoyi-env/bin/activate

# Installer les dépendances de base
pip install numpy pytest
```

### 6.2 Installer Ollama + Mistral (LLM local)
```bash
# Installer Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Télécharger Mistral 7B (~4GB)
ollama pull mistral

# Tester
ollama run mistral "Quelle est la capitale de la RDC ?"
# Réponse attendue : Kinshasa
# Ctrl+D pour quitter
```

### 6.3 Vérifier Nmap et Metasploit (déjà sur Kali)
```bash
nmap --version
msfconsole --version
```

---

## ÉTAPE 7 — Déployer le code NZOYI

### 7.1 Extraire le projet
```bash
cd ~
source nzoyi-env/bin/activate
tar xzf nzoyi_v0.1.0.tar.gz
cd nzoyi
```

### 7.2 Lancer les tests de validation
```bash
python main.py --test
```

✅ Résultat attendu : 4/4 tests passent.

### 7.3 Premier lancement
```bash
python main.py --target 192.168.100.11 --profile stealth
```

---

## Checklist finale

- [ ] PC 2 : Ubuntu Server installé
- [ ] Réseau : câble Ethernet entre les 2 PC
- [ ] Réseau : PC 1 = 192.168.100.10, PC 2 = 192.168.100.11
- [ ] Réseau : ping bidirectionnel OK
- [ ] Suricata : installé et configuré sur PC 2
- [ ] Services : SSH + Apache + FTP sur PC 2
- [ ] Baseline : scan Nmap depuis PC 1 → alertes Suricata sur PC 2
- [ ] Kali : Python venv + NZOYI + Ollama + Mistral
- [ ] NZOYI : `python main.py --test` → 4/4 OK
