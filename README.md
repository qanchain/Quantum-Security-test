# Quantum-Security-test

OpenSSL TLS Audit:
openssl s_client -connect example.com:443 -tlsextdebug 2>&1 | grep -E "TLS|Protocol"
nmap --script ssl-cert,ssl-enum-ciphers -p 443 example.com

SSH Key Algorithm Assessment:
ssh -Q key-sig | grep -E "rsa|ecdsa"
sshd -T | grep keyalgorithms

Nmap Quantum Vulnerability Scan:
nmap --script ssl-cert,ssl-enum-ciphers -p 443,22,25,587,993,995 <target_ip_range> -oA quantum_scan_results
grep -L "ECDHE" quantum_scan_results.nmap

SSH Configuration Hardening:
 Edit /etc/ssh/sshd_config
sudo nano /etc/ssh/sshd_config

Add or modify the following lines:
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp521
HostKeyAlgorithms ssh-ed25519,rsa-sha2-512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com

Certificate Transparency Log Query:
 Using crt.sh to monitor certificates
curl -s "https://crt.sh/?q=example.com&output=json" | jq '.[] | {id, name_value, not_before, issuer_name}'

Windows Registry Commands for Disabling Weak Ciphers:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f

AWS CLI to Identify Non-Compliant S3 Buckets:
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' | xargs -I {} aws s3api get-bucket-policy-status --bucket {} --query '{Bucket: PolicyStatus.IsPublic}' --output text 2>/dev/null

 Python PQC Key Generator
 Example using a PQC library like liboqs-python
from oqs import KeyEncapsulation

Select a PQC algorithm (e.g., Kyber)
kem_alg = "Kyber512"
client = KeyEncapsulation(kem_alg)
public_key = client.generate_keypair()

Save the public key
with open("client_public_key.pem", "wb") as pub_file:
pub_file.write(public_key)

print(f"Generated public key for {kem_alg}")

