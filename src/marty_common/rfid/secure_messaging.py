"""Secure Messaging for ICAO Passport Communication.

Implements Basic Access Control (BAC), Extended Access Control (EAC),
and PACE (Password Authenticated Connection Establishment) protocols.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


@dataclass
class BACKeys:
    """Basic Access Control keys derived from MRZ."""

    k_enc: bytes  # Encryption key
    k_mac: bytes  # MAC key
    k_seed: bytes  # Seed key


@dataclass
class SessionKeys:
    """Session keys for secure messaging."""

    k_s_enc: bytes  # Session encryption key
    k_s_mac: bytes  # Session MAC key
    ssc: int  # Send Sequence Counter


class SecureMessaging:
    """Handles secure messaging protocols for passport communication."""

    def __init__(self) -> None:
        self.session_keys: Optional[SessionKeys] = None
        self.logger = logging.getLogger(__name__)

    def derive_bac_keys(
        self, passport_number: str, date_of_birth: str, date_of_expiry: str
    ) -> BACKeys:
        """Derive BAC keys from MRZ data.

        Args:
            passport_number: Passport number from MRZ
            date_of_birth: Date of birth (YYMMDD)
            date_of_expiry: Date of expiry (YYMMDD)

        Returns:
            BACKeys containing encryption and MAC keys
        """
        # Construct MRZ information for key derivation
        mrz_info = f"{passport_number}{self._calculate_check_digit(passport_number)}"
        mrz_info += f"{date_of_birth}{self._calculate_check_digit(date_of_birth)}"
        mrz_info += f"{date_of_expiry}{self._calculate_check_digit(date_of_expiry)}"

        # Pad to ensure consistent length
        mrz_info = mrz_info.ljust(24, "<")

        # SHA-1 hash of MRZ information
        k_seed = hashlib.sha1(mrz_info.encode("ascii")).digest()[:16]

        # Derive encryption and MAC keys
        k_enc = self._derive_key(k_seed, b"\x00\x00\x00\x01")
        k_mac = self._derive_key(k_seed, b"\x00\x00\x00\x02")

        self.logger.debug("BAC keys derived from MRZ data")

        return BACKeys(k_enc=k_enc, k_mac=k_mac, k_seed=k_seed)

    def _calculate_check_digit(self, data: str) -> str:
        """Calculate MRZ check digit."""
        weights = [7, 3, 1]
        total = 0

        for i, char in enumerate(data):
            if char.isdigit():
                value = int(char)
            elif char == "<":
                value = 0
            else:
                # Convert letters to numbers (A=10, B=11, etc.)
                value = ord(char.upper()) - ord("A") + 10

            total += value * weights[i % 3]

        return str(total % 10)

    def _derive_key(self, k_seed: bytes, counter: bytes) -> bytes:
        """Derive encryption/MAC key from seed."""
        # ICAO key derivation using SHA-1
        data = k_seed + counter
        hash_result = hashlib.sha1(data).digest()

        # Adjust parity bits for DES compatibility
        key = bytearray(hash_result[:8])
        for i in range(8):
            # Set parity bit
            parity = 0
            for j in range(7):
                if (key[i] >> j) & 1:
                    parity ^= 1
            key[i] = (key[i] & 0xFE) | parity

        return bytes(key)

    def perform_basic_access_control(
        self, bac_keys: BACKeys, challenge: bytes
    ) -> tuple[bytes, bytes]:
        """Perform Basic Access Control authentication.

        Args:
            bac_keys: BAC keys derived from MRZ
            challenge: 8-byte challenge from passport

        Returns:
            Tuple of (authentication_command, expected_response)
        """
        # Generate random number for mutual authentication
        rnd_ic = challenge  # Challenge from passport
        rnd_ifd = b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0"  # Random from reader

        # Compute authentication data
        s = rnd_ifd + rnd_ic

        # Encrypt S with BAC encryption key
        cipher = self._create_3des_cipher(bac_keys.k_enc)
        encryptor = cipher.encryptor()
        e_ifd = encryptor.update(s) + encryptor.finalize()

        # Compute MAC
        m_ifd = self._compute_mac(bac_keys.k_mac, e_ifd)

        # Authentication command
        auth_cmd = e_ifd + m_ifd

        # Expected response format
        expected_s = rnd_ic + rnd_ifd  # Reversed order
        cipher = self._create_3des_cipher(bac_keys.k_enc)
        encryptor = cipher.encryptor()
        expected_e_ic = encryptor.update(expected_s) + encryptor.finalize()

        self.logger.debug("BAC authentication data computed")

        return auth_cmd, expected_e_ic

    def derive_session_keys(self, bac_keys: BACKeys, rnd_ic: bytes, rnd_ifd: bytes) -> SessionKeys:
        """Derive session keys from BAC keys and random numbers."""
        # Key seed for session keys
        k_seed = self._xor_bytes(rnd_ic, rnd_ifd)

        # Derive session keys
        k_s_enc = self._derive_key(k_seed, b"\x00\x00\x00\x01")
        k_s_mac = self._derive_key(k_seed, b"\x00\x00\x00\x02")

        # Initialize Send Sequence Counter
        ssc = int.from_bytes(rnd_ic[-4:] + rnd_ifd[-4:], "big")

        session_keys = SessionKeys(k_s_enc=k_s_enc, k_s_mac=k_s_mac, ssc=ssc)
        self.session_keys = session_keys

        self.logger.debug("Session keys derived")

        return session_keys

    def encrypt_command(self, apdu: bytes) -> bytes:
        """Encrypt APDU command using secure messaging."""
        if not self.session_keys:
            msg = "No session keys available"
            raise ValueError(msg)

        # Increment SSC
        self.session_keys.ssc += 1

        # Create secure messaging APDU
        # This is a simplified implementation - full implementation
        # would handle proper padding and MAC calculation

        encrypted_data = self._encrypt_data(apdu[5:], self.session_keys.k_s_enc)
        mac_data = self._compute_mac(self.session_keys.k_s_mac, apdu[:4] + encrypted_data)

        # Construct secure APDU
        secure_apdu = apdu[:4] + encrypted_data + mac_data

        return secure_apdu

    def decrypt_response(self, response: bytes) -> bytes:
        """Decrypt APDU response using secure messaging."""
        if not self.session_keys:
            msg = "No session keys available"
            raise ValueError(msg)

        # Extract encrypted data and MAC
        encrypted_data = response[:-10]  # Assuming 8-byte MAC + 2-byte status
        received_mac = response[-10:-2]
        status_word = response[-2:]

        # Verify MAC
        expected_mac = self._compute_mac(self.session_keys.k_s_mac, encrypted_data + status_word)

        if received_mac != expected_mac:
            msg = "MAC verification failed"
            raise ValueError(msg)

        # Decrypt data
        decrypted_data = self._decrypt_data(encrypted_data, self.session_keys.k_s_enc)

        return decrypted_data + status_word

    def _create_3des_cipher(self, key: bytes):
        """Create 3DES cipher for encryption/decryption."""
        # Extend 8-byte key to 24-byte for 3DES
        key_3des = key + key + key[:8]
        return Cipher(algorithms.TripleDES(key_3des), modes.CBC(b"\x00" * 8))

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data using session encryption key."""
        cipher = self._create_3des_cipher(key)
        encryptor = cipher.encryptor()

        # Pad data to block size
        padded_data = self._pad_data(data, 8)

        return encryptor.update(padded_data) + encryptor.finalize()

    def _decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data using session encryption key."""
        cipher = self._create_3des_cipher(key)
        decryptor = cipher.decryptor()

        decrypted = decryptor.update(data) + decryptor.finalize()

        # Remove padding
        return self._unpad_data(decrypted)

    def _compute_mac(self, key: bytes, data: bytes) -> bytes:
        """Compute MAC using session MAC key."""
        # Pad data
        padded_data = self._pad_data(data, 8)

        # Compute MAC using CBC-MAC
        cipher = self._create_3des_cipher(key)
        encryptor = cipher.encryptor()

        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        # Return last 8 bytes as MAC
        return encrypted[-8:]

    def _pad_data(self, data: bytes, block_size: int) -> bytes:
        """Apply PKCS#7 padding."""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding

    def _unpad_data(self, data: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """XOR two byte arrays."""
        return bytes(x ^ y for x, y in zip(a, b, strict=False))

    def setup_pace_protocol(self, password: str) -> bool:
        """Setup PACE (Password Authenticated Connection Establishment).

        PACE is a more secure alternative to BAC introduced in ICAO Doc 9303.
        """
        # PACE implementation would go here
        # This is a placeholder for the more complex PACE protocol
        self.logger.info("PACE protocol setup requested (not yet implemented)")
        return False

    def setup_eac_protocol(self, ca_reference: bytes) -> bool:
        """Setup EAC (Extended Access Control) for sensitive biometric data.

        EAC provides additional security for accessing fingerprint and iris data.
        """
        # EAC implementation would go here
        self.logger.info("EAC protocol setup requested (not yet implemented)")
        return False
