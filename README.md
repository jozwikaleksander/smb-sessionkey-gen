# SMB2 Session Key Generator

This script generates random decrypted SMB2 session key. This key is used in NTLM authentication mechanism. 
Generating the key allows us to decrypt SMB communication in PCAP file (for example in Wireshark). More information you will find [here](https://aleksanderjozwik.com/write-ups/entries/thm/block/index.html).

I found the original script [here](https://medium.com/maverislabs/decrypting-smb3-traffic-with-just-a-pcap-absolutely-maybe-712ed23ff6a2) while trying to solve [TryHackMe Block CTF](https://tryhackme.com/r/room/blockroom) and created my own version of it in Python 3.

# 📦 Installation
```
git clone https://github.com/jozwikaleksander/smb-sessionkey-gen.git
cd smb-sessionkey-gen
pip3 install -r requirements.txt
```

# ❔ Help
```
usage: SMB Session Key Generator [-h] -u USER -d DOMAIN -n NTPROOFSTR -k KEY [-p PASSWORD] [--ntHash NTHASH] [-v]

Generates random decrypted SMB2 session key

options:
  -h, --help            show this help message and exit
  -u USER, --user USER  User name
  -d DOMAIN, --domain DOMAIN
                        Domain name
  -n NTPROOFSTR, --ntproofstr NTPROOFSTR
                        NTProofStr (hex encoded)
  -k KEY, --key KEY     Encrypted Session Key (hex encoded)
  -p PASSWORD, --password PASSWORD
                        User's password
  --ntHash NTHASH       NT hash in hex
  -v, --verbose         Increase output verbosity
```

# 🖥️ Usage

**Required parameters are:** username (-u), domain name (-d), NTPROOFSTR (-n), encrypted session key (in hex, -k), password (-p) or NTLM hash (--ntHash).

```bash
$ python3 smb-key-gen.py -u mrealman --ntHash 1f9175a516211660c7a8143b0f36ab44 -d WORKGROUP -n 16e816dead16d4ca7d5d6dee4a015c14 -k fde53b54cb676b9bbf0fb1fbef384698

20a642c086ef74eee26277bf1d0cff8c

```
You can also use verbose flag (-v) to get more information.

```bash
$ python3 smb-key-gen.py -u mrealman --ntHash 1f9175a516211660c7a8143b0f36ab44 -d WORKGROUP -n 16e816dead16d4ca7d5d6dee4a015c14 -k fde53b54cb676b9bbf0fb1fbef384698 -v
INFO: Username: MREALMAN
INFO: Domain: WORKGROUP
INFO: NT hash: 1f9175a516211660c7a8143b0f36ab44
INFO: Ntproofstr: 16e816dead16d4ca7d5d6dee4a015c14
INFO: Session key: fde53b54cb676b9bbf0fb1fbef384698
INFO: Random generated session key: 20a642c086ef74eee26277bf1d0cff8c

```

# 👤 Credits
Project was made by Aleksander Jóźwik (@jozwikaleksander).
