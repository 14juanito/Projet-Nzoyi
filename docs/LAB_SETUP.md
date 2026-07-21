# Configuration du laboratoire — Réseau isolé KVM/libvirt

> Environnement expérimental du projet NZOYI.
> Deux machines sur un réseau isolé, virtualisées via KVM/QEMU (libvirt) sur un hôte Kali Linux bare-metal.
> Objectif : garantir un banc de test **reproductible** et **hermétique** pour la mesure de résilience des IDS.

---

## 1. Topologie

| Machine | Rôle | Interface | Réseau libvirt | IP |
| --- | --- | --- | --- | --- |
| **Attaquant** — Kali Linux (hôte bare-metal) | NZOYI, Nmap, orchestrateur | — | `nzoyi-lab` | `192.168.100.10` |
| **Cible/Défenseur** — Ubuntu Server 24.04.4 LTS (VM) | Suricata, RF Oracle (Flask), SSH, Apache | `enp2s0` | `nzoyi-lab` (isolé) | `192.168.100.11` |
| — | Provisioning / mises à jour | `enp1s0` | `default` (NAT) | `192.168.122.x` (DHCP) |

La VM cible possède **deux cartes réseau** :

- `enp2s0` → réseau **isolé** `nzoyi-lab` (192.168.100.0/24) — **plan expérimental**, aucun egress.
- `enp1s0` → réseau **NAT** `default` (192.168.122.0/24) — uniquement pour l'installation des paquets et mises à jour. À déconnecter avant toute campagne de mesure formelle si l'on veut un isolement strict.

---

## 2. Réseaux libvirt

Deux réseaux distincts sont définis côté hôte :

```bash
# Vérifier les réseaux existants
virsh net-list --all
```

Résultat attendu :

```
 Name        State    Autostart   Persistent
--------------------------------------------------
 default     active   yes         yes
 nzoyi-lab   active   yes         yes
```

### 2.1 Réseau isolé `nzoyi-lab`

Définition (`nzoyi-lab.xml`) — réseau **isolé** (pas de `<forward>`, donc aucun routage vers l'extérieur) :

```xml
<network>
  <name>nzoyi-lab</name>
  <bridge name='virbr-nzoyi' stp='on' delay='0'/>
  <ip address='192.168.100.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='192.168.100.10' end='192.168.100.50'/>
    </dhcp>
  </ip>
</network>
```

> **Note d'isolement** : l'absence de balise `<forward mode='nat'/>` est volontaire. C'est ce qui garantit qu'aucun paquet ne quitte le réseau `nzoyi-lab`. Exigence éthique + validité expérimentale.

Application :

```bash
virsh net-define nzoyi-lab.xml
virsh net-start nzoyi-lab
virsh net-autostart nzoyi-lab
```

### 2.2 URI libvirt par défaut

Pour éviter de préfixer chaque commande `virsh` par `qemu:///system`, ajouter dans `~/.zshrc` (Kali) :

```bash
export LIBVIRT_DEFAULT_URI=qemu:///system
```

Puis :

```bash
source ~/.zshrc
```

---

## 3. Vérification de la connectivité (banc validé)

### 3.1 Adresses de la cible

Sur la VM cible :

```bash
ip a
```

On doit retrouver **les deux** interfaces :

```
enp1s0 → 192.168.122.x/24   (NAT, provisioning)
enp2s0 → 192.168.100.11/24  (isolé, plan expérimental)
```

> **Piège** : l'écran de bienvenue d'Ubuntu (MOTD) n'affiche que la première interface (`enp1s0`, 192.168.122.x). Ce n'est **pas** un signe que la cible est mal configurée — vérifier systématiquement avec `ip a`.

### 3.2 Atteignabilité depuis l'attaquant

Depuis Kali :

```bash
ping -c 4 192.168.100.11
```

Attendu : `0% packet loss`, latence < 1 ms (réseau virtuel local).

---

## 4. Détecteur de signature — Suricata

### 4.1 État du service

Sur la cible :

```bash
sudo systemctl status suricata
```

Points à confirmer :

- `Active: active (running)`
- Version affichée (à épingler pour la reproductibilité) : **Suricata 8.0.6 RELEASE**, mode `SYSTEM`.

### 4.2 Interface écoutée — vérification par la preuve

Plutôt que d'auditer le YAML (chemin variable, droits root), **prouver** que Suricata voit le trafic du réseau isolé :

```bash
# Terminal cible : logs en direct
sudo tail -f /var/log/suricata/eve.json
```

```bash
# Terminal attaquant : générer du trafic
nmap -sV 192.168.100.11
```

Le fichier `eve.json` doit se remplir pendant le scan. Indicateurs de bon fonctionnement observés dans le flux `stats` :

- `rules_loaded: 52058` — ruleset ET Open chargé.
- `alert: > 0` — Suricata a réagi au trafic (537 alertes lors de notre scan de validation).
- `tcp / syn` incrémentés — capture effective du scan TCP.

> **Conclusion** : si `eve.json` bouge pendant le nmap, Suricata écoute la bonne carte (`enp2s0`). Inutile de modifier `suricata.yaml`.

### 4.3 Ruleset — épinglage de version (reproductibilité)

Consigner dans le dépôt la version exacte du ruleset et du moteur :

```
Suricata : 8.0.6 RELEASE
Règles chargées : 52058 (ET Open)
Date de capture baseline : 2026-07-21
```

---

## 5. Points de vigilance connus

### 5.1 Socket Suricata (non bloquant)

Au démarrage, Suricata peut afficher :

```
E: unix-manager: failed to create socket directory /var/run/suricata/: Permission denied
W: unix-manager: Unable to create unix command socket
```

Cela casse **uniquement** l'interrogation en direct via `suricatasc`. Comme l'agent Evaluation lit directement `eve.json`, ce n'est pas bloquant. À corriger seulement si un accès socket devient nécessaire.

### 5.2 Offloading NIC — À DÉSACTIVER pour les tests d'évasion

Sur `enp2s0` de la cible, les optimisations d'offloading coalescent les paquets et **annulent** les actions d'évasion par fragmentation / taille de paquet. À désactiver de façon persistante **avant la phase d'évasion** :

```bash
sudo ethtool -k enp2s0 | grep -E "generic|tcp-segmentation|large-receive"
# generic-receive-offload, generic-segmentation-offload,
# tcp-segmentation-offload, large-receive-offload  → doivent être "off"
```

> Non bloquant pour un run **sans évasion** (baseline), mais **critique** dès l'introduction de l'agent Evasion.

### 5.3 Snapshot de référence

Créer un snapshot propre de la cible pour réinitialiser l'état des flux Suricata entre les épisodes RL :

```bash
virsh snapshot-create-as --domain <nom-vm-cible> --name clean-baseline \
  --description "Etat propre avant campagne de mesure"
# Restauration entre épisodes :
virsh snapshot-revert --domain <nom-vm-cible> --snapshotname clean-baseline
```

---

## 6. Checklist de pré-vol (avant tout lancement NZOYI)

| Vérification | Commande | Attendu |
| --- | --- | --- |
| Cible sur réseau isolé | `ip a` (cible) | `enp2s0 → 192.168.100.11` |
| Attaquant → cible | `ping 192.168.100.11` (Kali) | 0% packet loss |
| Suricata actif | `systemctl status suricata` | active (running) |
| Suricata voit le trafic | `tail -f eve.json` + `nmap` | eve.json se remplit |
| Services cibles présents | `nmap -sV 192.168.100.11` | ports 22 / 80 / 5000 ouverts |
| API RF (Flask) joignable | `nmap -sV 192.168.100.11` | port **5000** Werkzeug/Python |
| Offloading désactivé (si évasion) | `ethtool -k enp2s0` | GRO/GSO/TSO/LRO = off |

---

*Banc validé le 2026-07-21 — Ubuntu Server 24.04.4 LTS, Suricata 8.0.6, KVM/QEMU sur Kali Linux.*
