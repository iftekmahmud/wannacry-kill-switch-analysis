# WannaCry: A Technical Analysis of its Exploitation, Spread, and Neutralization

WannaCry is one of the most notorious ransomware attacks, launched in May 2017, that exploited the Windows **SMBv1 protocol vulnerability** using the EternalBlue exploit. This attack leveraged **worm-like behavior** to propagate across networks, targeting systems that had not applied Microsoft’s critical **MS17-010 security patch.**

Once infected, the ransomware encrypted files using a hybrid approach—**AES-128 for file encryption** and **RSA for key exchange**—and demanded ransom payments in Bitcoin, locking victims out of their data. WannaCry caused widespread disruption, crippling over **200,000 systems in 150+ countries**, with major impacts on healthcare, transportation, and corporate networks.

----

## How WannaCry Exploited the EternalBlue Vulnerability

The core of WannaCry’s propagation relied on EternalBlue, an exploit that targeted a vulnerability in the Server Message Block (SMB) protocol, commonly used for file sharing across networks.

**How EternalBlue Works:**

- It sends specially crafted packets to exploit SMBv1’s lack of input sanitization.
- Once exploited, the attacker can execute arbitrary code remotely, gaining **SYSTEM-level privileges.**

Here’s a simplified explanation of the EternalBlue exploit mechanism:
  
  ```python
  import socket
  
  def exploit_smb(target_ip):
      try:
          payload = b"\x00\x00\x00..."  # Simulated crafted packet
          connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          connection.connect((target_ip, 445))  # SMB port
          connection.send(payload)
          print(f"Successfully exploited SMB on {target_ip}!")
      except:
          print(f"Failed to exploit {target_ip}.")
      finally:
          connection.close()
  
  target = "192.168.0.10"
  exploit_smb(target)
  ```

EternalBlue’s capability to execute arbitrary code opened the door for WannaCry’s payload deployment.

----

## Encryption Mechanism of WannaCry

WannaCry uses a **hybrid encryption model** to lock files:

1. **AES-128:** Used to encrypt individual files on the victim's machine.
2. **RSA-2048:** Used to encrypt the AES keys, ensuring that the decryption process can only be initiated with the attacker’s private RSA key.

  Pseudo-code Example of the encryption process:
  
  ```python
  from cryptography.hazmat.primitives.asymmetric import rsa
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  
  # Generate RSA keys (attacker-controlled)
  private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
  public_key = private_key.public_key()
  
  # Generate AES key
  aes_key = os.urandom(16)
  
  def encrypt_file_with_aes(file_path, aes_key):
      cipher = Cipher(algorithms.AES(aes_key), modes.CBC(os.urandom(16)))
      encryptor = cipher.encryptor()
      with open(file_path, "rb") as file:
          data = file.read()
      encrypted_data = encryptor.update(data) + encryptor.finalize()
      with open(file_path, "wb") as file:
          file.write(encrypted_data)
  
  # Encrypt AES key with RSA
  encrypted_aes_key = public_key.encrypt(aes_key, ...)
  
  # Simulate encryption of files
  encrypt_file_with_aes("document.txt", aes_key)
  ```

This dual-layer encryption ensures victims cannot decrypt their files without paying the ransom.

----

## The Role of the Kill Switch

One of WannaCry’s most fascinating features was its **kill switch**, a security measure possibly added to allow the attackers to terminate the operation if needed. Before encrypting files or propagating, WannaCry attempted to connect to a predefined domain name. If the domain was active, the malware halted its execution.

Marcus Hutchins, a reverse engineer, discovered this functionality while analyzing the ransomware’s binary in a sandbox. He registered the unclaimed domain for $10, effectively activating the kill switch and stopping WannaCry’s spread globally.

Here’s how the kill switch might have been implemented:

```python
import requests

def wannacry_execution():
    kill_switch_url = "http://unregistered-killswitch-domain.com"
    try:
        response = requests.get(kill_switch_url, timeout=5)
        if response.status_code == 200:
            print("Kill switch triggered. Exiting malware.")
            return
    except:
        pass

    print("Kill switch inactive. Encrypting files and spreading...")
    # Further ransomware behavior
    # encrypt_files()
    # spread_to_other_hosts()

wannacry_execution()
```

-----

## Post-Mortem Analysis and Lessons Learned

- **Impact of Patching:** Microsoft had released the **MS17-010 patch** two months before the attack. Organizations that applied the patch were immune to WannaCry.
- **Reverse Engineering and Incident Response:** Marcus Hutchins' work demonstrates the importance of **reverse engineering** and **malware analysis** in mitigating active threats.
- **Hybrid Encryption Threat:** WannaCry’s use of dual-layer encryption highlights the sophistication of modern ransomware and the challenges in recovery without backups or private keys.

-----

## Tools for Researchers to Analyze Malware

If you want to delve into cybersecurity research and malware analysis, consider these tools:

- **Wireshark:** To analyze network traffic and identify malware communication.
- **IDA Pro or Ghidra:** For reverse-engineering binaries.
- **Remnux:** A Linux distribution specifically tailored for malware analysis.
- **Cuckoo Sandbox:** For dynamic malware behavior analysis.

-----

## Final Thoughts

WannaCry exemplifies how vulnerabilities can be weaponized on a global scale and how timely action (like Marcus Hutchins’ kill-switch discovery) can mitigate widespread damage. The attack underscores the critical importance of **patch management**, **network segmentation**, and ongoing vigilance in cybersecurity practices.

----
