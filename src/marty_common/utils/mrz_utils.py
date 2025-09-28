"""
Machine Readable Zone (MRZ) parsing and generation utilities.

Implements MRZ processing according to ICAO Doc 9303 Part 3 and Part 4.
"""

import re
from datetime import datetime

from ..models.passport import Gender, MRZData


class MRZException(Exception):
    """Exception raised for errors in the MRZ handling."""


class MRZParser:
    """Parser for Machine Readable Zone (MRZ) data according to ICAO Doc 9303."""

    @staticmethod
    def calculate_check_digit(input_string: str) -> str:
        """
        Calculate the check digit as per ICAO Doc 9303 specifications.

        Args:
            input_string: String to calculate check digit for

        Returns:
            Single character check digit
        """
        weights = [7, 3, 1]
        total = 0

        for i, char in enumerate(input_string):
            if char == "<":
                value = 0
            elif char.isdigit():
                value = int(char)
            elif char.isalpha():
                # A = 10, B = 11, ..., Z = 35
                value = ord(char.upper()) - ord("A") + 10
            else:
                value = 0  # For any other character

            total += value * weights[i % 3]

        return str(total % 10)

    @staticmethod
    def validate_check_digit(input_string: str, check_digit: str) -> bool:
        """
        Validate a check digit against an input string.

        Args:
            input_string: String to validate check digit for
            check_digit: The check digit to validate

        Returns:
            True if valid, False otherwise
        """
        calculated = MRZParser.calculate_check_digit(input_string)
        return calculated == check_digit

    @staticmethod
    def clean_name(name: str) -> str:
        """
        Clean a name by converting it to uppercase and replacing invalid characters with '<'.

        Args:
            name: Name to clean

        Returns:
            Cleaned name suitable for MRZ
        """
        # Remove diacritical marks and special characters
        # Only allow A-Z, spaces and hyphens
        # Replace spaces with '<'
        return re.sub(r"[^A-Z\-]", "<", name.upper().replace(" ", "<"))

    @staticmethod
    def _split_lines(mrz: str) -> list[str]:
        """Split MRZ payload into two TD3 lines."""

        raw = mrz.strip()

        if "\n" in raw:
            lines = raw.split("\n")
        elif len(raw) == 88:
            lines = [raw[:44], raw[44:]]
        else:
            lines = [raw]

        return lines

    @classmethod
    def _normalize_whitespace(cls, value: str) -> str:
        parts = [segment for segment in value.replace("<", " ").split() if segment]
        return " ".join(parts)

    @classmethod
    def _validate_date(cls, date_value: str, label: str) -> None:
        if not date_value.isdigit() or len(date_value) != 6:
            msg = f"{label} must consist of six digits"
            raise MRZException(msg)

        try:
            datetime.strptime(date_value, "%y%m%d")
        except ValueError as exc:
            msg = f"Invalid {label} value"
            raise MRZException(msg) from exc

    @classmethod
    def parse_td3_mrz(cls, mrz: str) -> MRZData:
        """
        Parse a TD3 format MRZ string (passport).

        Args:
            mrz: The MRZ string to parse (typically 2 lines of 44 characters)

        Returns:
            MRZData object containing the parsed data

        Raises:
            MRZException: If the MRZ format is invalid
        """
        lines = cls._split_lines(mrz)

        if len(lines) != 2:
            msg = "TD3 MRZ must have exactly 2 lines"
            raise MRZException(msg)

        if len(lines[0]) != 44 or len(lines[1]) != 44:
            msg = "TD3 MRZ lines must be exactly 44 characters long"
            raise MRZException(msg)

        # First line: P<ISSUING_COUNTRY<SURNAME<<GIVEN_NAMES
        line1 = lines[0]
        document_type = line1[0]
        if document_type != "P":
            msg = f"Expected document type 'P', found '{document_type}'"
            raise MRZException(msg)

        issuing_country = line1[2:5]

        name_part = line1[5:]
        name_parts = name_part.split("<<", 1)
        surname = cls._normalize_whitespace(name_parts[0])
        given_section = name_parts[1] if len(name_parts) > 1 else ""
        given_names = cls._normalize_whitespace(given_section)

        # Second line: DOCUMENT_NUMBER<CHECK_DIGIT<NATIONALITY<DOB<CHECK_DIGIT<GENDER<DOE<CHECK_DIGIT<PERSONAL_NUMBER<CHECK_DIGIT<COMPOSITE_CHECK_DIGIT
        line2 = lines[1]
        # For TD3, document number field is 9 chars and may contain fillers '<'.
        # Check digit is computed over the field INCLUDING fillers, so do not strip for check.
        document_number_field = line2[0:9]
        doc_check_digit = line2[9]
        if not cls.validate_check_digit(document_number_field, doc_check_digit):
            msg = (
                f"Invalid document number check digit: {document_number_field} -> {doc_check_digit}"
            )
            raise MRZException(msg)

        document_number = document_number_field.replace("<", "")

        nationality = line2[10:13]

        date_of_birth = line2[13:19]
        dob_check_digit = line2[19]

        cls._validate_date(date_of_birth, "date of birth")

        if not cls.validate_check_digit(date_of_birth, dob_check_digit):
            msg = f"Invalid date of birth check digit: {date_of_birth} -> {dob_check_digit}"
            raise MRZException(msg)

        gender_code = line2[20]
        if gender_code == "M":
            gender = Gender.MALE
        elif gender_code == "F":
            gender = Gender.FEMALE
        else:
            gender = Gender.UNSPECIFIED

        date_of_expiry = line2[21:27]
        doe_check_digit = line2[27]

        cls._validate_date(date_of_expiry, "date of expiry")

        if not cls.validate_check_digit(date_of_expiry, doe_check_digit):
            msg = f"Invalid date of expiry check digit: {date_of_expiry} -> {doe_check_digit}"
            raise MRZException(msg)

        personal_number_field = line2[28:42]
        personal_number_check_digit = line2[42]
        # Validate personal number using the field with fillers, but treat all '<' as zero value
        # An empty field (all '<') will validate against its computed digit (often '0').
        if not cls.validate_check_digit(personal_number_field, personal_number_check_digit):
            msg = f"Invalid personal number check digit: {personal_number_field} -> {personal_number_check_digit}"
            raise MRZException(msg)
        personal_number = personal_number_field.replace("<", "") or None

        # Validation of composite check digit
        composite_check_digit = line2[43]
        composite_string = (
            document_number_field
            + doc_check_digit
            + date_of_birth
            + dob_check_digit
            + date_of_expiry
            + doe_check_digit
            + personal_number_field
            + personal_number_check_digit
        )

        if not cls.validate_check_digit(composite_string, composite_check_digit):
            msg = "Invalid composite check digit"
            raise MRZException(msg)

        return MRZData(
            document_type=document_type,
            issuing_country=issuing_country,
            document_number=document_number,
            surname=surname,
            given_names=given_names,
            nationality=nationality,
            date_of_birth=date_of_birth,
            gender=gender,
            date_of_expiry=date_of_expiry,
            personal_number=personal_number,
        )

    @classmethod
    def parse_mrz(cls, mrz: str) -> MRZData:
        """
        Parse any type of MRZ string. Currently only TD3 (passport) is supported.

        Args:
            mrz: The MRZ string to parse

        Returns:
            MRZData object containing the parsed data

        Raises:
            MRZException: If the MRZ format is invalid or unsupported
        """
        lines = cls._split_lines(mrz)
        if len(lines) == 2 and all(len(line) == 44 for line in lines):
            return cls.parse_td3_mrz("\n".join(lines))
        msg = "Unsupported MRZ format"
        raise MRZException(msg)


class MRZFormatter:
    """Formatter for Machine Readable Zone (MRZ) data according to ICAO Doc 9303."""

    @staticmethod
    def format_name(name: str, max_length: int) -> str:
        """
        Format a name for MRZ by converting to uppercase and replacing spaces with '<'.

        Args:
            name: Name to format
            max_length: Maximum allowed length

        Returns:
            Formatted name
        """
        cleaned_name = MRZParser.clean_name(name)
        if len(cleaned_name) > max_length:
            return cleaned_name[:max_length]
        return cleaned_name

    @staticmethod
    def format_document_number(number: str, total_length: int = 9) -> str:
        """
        Format a document number for MRZ.

        Args:
            number: Document number to format
            total_length: Total length including filler characters

        Returns:
            Formatted document number
        """
        # Keep only alphanumeric characters and uppercase
        cleaned_number = re.sub(r"[^A-Z0-9]", "", number.upper())

        # Pad with '<' if shorter than total_length
        if len(cleaned_number) < total_length:
            return cleaned_number + "<" * (total_length - len(cleaned_number))

        # Truncate if longer
        return cleaned_number[:total_length]

    @staticmethod
    def generate_td3_mrz(data: MRZData) -> str:
        """
        Generate a TD3 format MRZ string (passport).

        Args:
            data: MRZData object containing the passport data

        Returns:
            Formatted MRZ string
        """
        # First line
        line1 = data.document_type
        line1 += "<"  # Filler
        line1 += data.issuing_country.upper()

        surname = MRZParser.clean_name(data.surname)
        given_names = MRZParser.clean_name(data.given_names)

        line1 += surname + "<<" + given_names
        line1 = line1[:44].ljust(44, "<")

        # Second line
        document_number_formatted = MRZFormatter.format_document_number(data.document_number)
        document_check_digit = MRZParser.calculate_check_digit(document_number_formatted)

        line2 = document_number_formatted + document_check_digit
        line2 += data.nationality.upper()

        dob_check_digit = MRZParser.calculate_check_digit(data.date_of_birth)
        line2 += data.date_of_birth + dob_check_digit

        line2 += data.gender.value

        doe_check_digit = MRZParser.calculate_check_digit(data.date_of_expiry)
        line2 += data.date_of_expiry + doe_check_digit

        # Personal number with check digit
        personal_number_raw = (data.personal_number or "").upper()
        personal_number_clean = re.sub(r"[^A-Z0-9<]", "", personal_number_raw)
        personal_number_formatted = personal_number_clean[:14].ljust(14, "<")
        personal_number_check_digit = MRZParser.calculate_check_digit(personal_number_formatted)

        line2 += personal_number_formatted + personal_number_check_digit

        # Calculate composite check digit
        composite_string = (
            document_number_formatted
            + document_check_digit
            + data.date_of_birth
            + dob_check_digit
            + data.date_of_expiry
            + doe_check_digit
            + personal_number_formatted
            + personal_number_check_digit
        )
        composite_check_digit = MRZParser.calculate_check_digit(composite_string)

        line2 += composite_check_digit

        return line1 + "\n" + line2
