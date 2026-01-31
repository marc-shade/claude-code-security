"""
TLS Manager: ECDSA P-256 cluster CA. [Tier 4]

Self-signed cluster CA with per-node certificates for
TLS-secured inter-node communication.

Certificate Hierarchy:
    Cluster CA (10-year, ECDSA P-256)
    +-- Node certificates (1-year, signed by CA)
"""

import logging
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

from claude_code_security import config

logger = logging.getLogger("claude_code_security.tls_manager")


class TLSManager:
    """
    Manages TLS certificates for cluster inter-node communication.

    Creates a self-signed cluster CA and issues per-node certificates.
    CA private key is encrypted in the KeyVault.
    """

    def __init__(self, certs_dir: Optional[Path] = None):
        self.certs_dir = certs_dir or config.CERTS_DIR
        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self._ca_cert = None
        self._ca_key = None

    def _get_vault(self):
        from claude_code_security.key_vault import KeyVault
        return KeyVault()

    def _get_or_create_ca(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        ca_cert_path = self.certs_dir / "cluster_ca.pem"

        if ca_cert_path.exists():
            try:
                vault = self._get_vault()
                ca_key_pem = vault.load_key(config.CA_KEY_VAULT_NAME)
                if ca_key_pem:
                    self._ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
                    self._ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
                    return self._ca_cert, self._ca_key
            except Exception as e:
                logger.warning(f"Failed to load existing CA: {e}")

        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Claude Code Cluster CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Claude Code Security"),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(
                datetime.now(timezone.utc) + timedelta(days=config.CA_VALIDITY_YEARS * 365)
            )
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))

        ca_key_pem = ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        vault = self._get_vault()
        vault.store_key(config.CA_KEY_VAULT_NAME, ca_key_pem)

        self._ca_cert = ca_cert
        self._ca_key = ca_key
        logger.info("Generated new cluster CA certificate")
        return ca_cert, ca_key

    def generate_node_cert(self, node_id: str) -> Dict:
        """Generate a TLS certificate for a node."""
        import re
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$', node_id):
            raise ValueError(f"Invalid node_id: must match [a-zA-Z0-9][a-zA-Z0-9._-]{{0,63}}")

        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        ca_cert, ca_key = self._get_or_create_ca()
        node_key = ec.generate_private_key(ec.SECP256R1())

        sans = [
            x509.DNSName(node_id),
            x509.DNSName(f"{node_id}.local"),
        ]
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, node_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Claude Code Cluster"),
        ])

        not_after = datetime.now(timezone.utc) + timedelta(days=config.NODE_CERT_VALIDITY_DAYS)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(node_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_encipherment=True,
                    content_commitment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        cert_path = self.certs_dir / f"{node_id}.pem"
        key_path = self.certs_dir / f"{node_id}.key"

        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            node_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        try:
            key_path.chmod(0o600)
        except OSError:
            pass

        logger.info(f"Generated TLS certificate for node: {node_id}")
        return {
            "node_id": node_id,
            "cert_path": str(cert_path),
            "key_path": str(key_path),
            "ca_cert_path": str(self.certs_dir / "cluster_ca.pem"),
            "expires": not_after.isoformat(),
            "sans": [node_id, f"{node_id}.local"],
        }

    def create_ssl_context(self, node_id: str, purpose: str = "client") -> ssl.SSLContext:
        """Create an SSL context for a node."""
        cert_path = self.certs_dir / f"{node_id}.pem"
        key_path = self.certs_dir / f"{node_id}.key"
        ca_cert_path = self.certs_dir / "cluster_ca.pem"

        if not cert_path.exists():
            self.generate_node_cert(node_id)

        if purpose == "server":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.load_verify_locations(str(ca_cert_path))
        ctx.verify_mode = ssl.CERT_REQUIRED
        if purpose == "client":
            ctx.check_hostname = True
        else:
            ctx.check_hostname = False
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def verify_cert(self, cert_path: Path) -> Dict:
        from cryptography import x509

        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            ca_cert_path = self.certs_dir / "cluster_ca.pem"
            if not ca_cert_path.exists():
                return {"valid": False, "error": "CA certificate not found"}

            ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
            try:
                from cryptography.hazmat.primitives.asymmetric import ec as ec_module
                ca_cert.public_key().verify(
                    cert.signature, cert.tbs_certificate_bytes,
                    ec_module.ECDSA(cert.signature_hash_algorithm),
                )
            except Exception:
                return {"valid": False, "error": "Signature verification failed"}

            now = datetime.now(timezone.utc)
            if now > cert.not_valid_after_utc:
                return {"valid": False, "error": "Certificate expired"}
            if now < cert.not_valid_before_utc:
                return {"valid": False, "error": "Certificate not yet valid"}

            return {
                "valid": True,
                "subject": cert.subject.rfc4514_string(),
                "expires": cert.not_valid_after_utc.isoformat(),
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def is_cert_expiring(self, node_id: str, days_threshold: int = 30) -> bool:
        from cryptography import x509
        cert_path = self.certs_dir / f"{node_id}.pem"
        if not cert_path.exists():
            return True
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            remaining = cert.not_valid_after_utc - datetime.now(timezone.utc)
            return remaining.days < days_threshold
        except Exception:
            return True

    def rotate_node_cert(self, node_id: str) -> Dict:
        cert_path = self.certs_dir / f"{node_id}.pem"
        if cert_path.exists():
            backup = self.certs_dir / f"{node_id}.pem.bak"
            cert_path.rename(backup)
        return self.generate_node_cert(node_id)

    def get_cert_inventory(self) -> List[Dict]:
        from cryptography import x509
        inventory = []
        for cert_file in sorted(self.certs_dir.glob("*.pem")):
            try:
                cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
                now = datetime.now(timezone.utc)
                remaining = cert.not_valid_after_utc - now
                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                    sans = [n.value for n in san_ext.value]
                except x509.ExtensionNotFound:
                    pass
                inventory.append({
                    "file": cert_file.name,
                    "subject": cert.subject.rfc4514_string(),
                    "expires": cert.not_valid_after_utc.isoformat(),
                    "remaining_days": remaining.days,
                    "is_ca": any(
                        ext.value.ca for ext in cert.extensions
                        if isinstance(ext.value, x509.BasicConstraints)
                    ),
                    "sans": sans,
                })
            except Exception as e:
                inventory.append({"file": cert_file.name, "error": str(e)})
        return inventory
