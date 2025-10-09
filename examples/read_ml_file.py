#!/usr/bin/env python3
"""
Read and display the contents of ICAO master list (.ml) files.
This tool reads real ICAO master lists in ASN.1 DER format.
"""

import sys
from pathlib import Path


def read_asn1_ml_file(data: bytes, file_path: Path) -> None:
    """Read a real ICAO master list in ASN.1 DER format."""
    print(f"�️  Reading: {file_path}")
    print("📋 ICAO Master List (ASN.1 DER format)")
    print(f"📁 File size: {len(data)} bytes")

    # Basic ASN.1 structure analysis
    if len(data) < 2:
        print("❌ File too small")
        return

    # ASN.1 SEQUENCE tag
    if data[0] == 0x30:
        print("✅ Valid ASN.1 SEQUENCE structure")

        # Try to extract length
        if data[1] & 0x80:
            # Long form length
            length_octets = data[1] & 0x7F
            if length_octets <= 4 and len(data) >= 2 + length_octets:
                total_length = 0
                for i in range(length_octets):
                    total_length = (total_length << 8) | data[2 + i]
                print(f"📏 ASN.1 length: {total_length} bytes")
        else:
            # Short form length
            total_length = data[1]
            print(f"📏 ASN.1 length: {total_length} bytes")
    else:
        print(f"⚠️  Unexpected tag: 0x{data[0]:02x} (expected 0x30 for SEQUENCE)")

    # Look for country codes and certificate patterns
    countries = []
    for i in range(len(data) - 2):
        if data[i : i + 2] == b"\\x13\\x02" and i + 4 < len(
            data
        ):  # PrintableString of length 2 (country code)
            cc = data[i + 2 : i + 4]
            if cc.isalpha() and cc.isupper():
                countries.append(cc.decode("ascii"))

    if countries:
        unique_countries = list(set(countries))
        print(f"🌍 Countries found: {', '.join(unique_countries)}")
        print(f"📊 Total country references: {len(countries)}")

    # Look for certificate markers
    cert_count = data.decode("latin-1", errors="ignore").count("-----BEGIN CERTIFICATE-----")
    if cert_count == 0:
        # Look for DER certificate patterns (0x30 0x82 for typical cert start)
        cert_count = 0
        for i in range(len(data) - 3):
            if data[i] == 0x30 and data[i + 1] == 0x82:
                cert_count += 1

    print(f"📜 Estimated certificates: {cert_count}")

    # Show hex preview
    hex_preview = " ".join(f"{b:02x}" for b in data[:32])
    if len(data) > 32:
        hex_preview += "..."
    print(f"🔍 Hex preview: {hex_preview}")


def read_ml_file(file_path: Path) -> None:
    """Read and display contents of a .ml file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if len(data) < 2:
            print("❌ File too small to be a valid .ml file")
            return

        # Check if this looks like ASN.1 DER format
        if data[0] == 0x30 and (data[1] & 0x80 or data[1] < 0x80):
            # ASN.1 SEQUENCE - this is the expected format for ICAO master lists
            read_asn1_ml_file(data, file_path)
        else:
            print(f"❓ Unexpected format - first bytes: {data[:6].hex()}")
            print("Expected ASN.1 DER format starting with 0x30")
            # Try to analyze anyway
            read_asn1_ml_file(data, file_path)

    except Exception as e:
        print(f"❌ Error reading .ml file: {e}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 read_ml_file.py <file.ml>")
        print("Reads ICAO master lists in ASN.1 DER format")
        sys.exit(1)

    file_path = Path(sys.argv[1])
    if not file_path.exists():
        print(f"❌ File not found: {file_path}")
        sys.exit(1)

    read_ml_file(file_path)


if __name__ == "__main__":
    main()
