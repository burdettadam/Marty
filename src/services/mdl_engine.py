# --- BEGIN Standard Library Imports ---
import io
import json
import logging
import os
import sys  # sys must be imported before path manipulation
import uuid
from concurrent import futures
from datetime import datetime, timedelta, timezone  # Ensure timedelta is imported

import grpc  # Added missing grpc import
import qrcode

# import time # Marked as unused in previous diagnostics
# import base64 # Marked as unused
# import hashlib # Marked as unused
# --- END Standard Library Imports ---
# --- BEGIN Third-Party Imports ---
from PIL import Image, ImageDraw, ImageFont
from qrcode.image.pil import PilImage  # Import PilImage factory

# import cv2 # Marked as unused
# import numpy as np # Marked as unused
# from pyzbar import pyzbar # Marked as unused
# --- END Third-Party Imports ---

# --- BEGIN Project-Specific Imports ---
# This block MUST be placed after all standard and third-party imports
# and before any 'from src...' imports.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Now, import from 'src'
from src.marty_common.grpc_logging import LoggingStreamerServicer
from src.marty_common.logging_config import setup_logging
from src.proto import document_signer_pb2  # For SignDocumentRequest
from src.proto import document_signer_pb2_grpc  # For DocumentSignerStub
from src.proto import (
    common_services_pb2_grpc,
    mdl_engine_pb2,
    mdl_engine_pb2_grpc,
)

# --- END Project-Specific Imports ---

# Module-level logger, will be initialized in serve() after setup_logging
logger = None

DEFAULT_FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
DEFAULT_FONT_SIZE = 10


class MDLEngineServicer(mdl_engine_pb2_grpc.MDLEngineServicer):
    def __init__(self, document_signer_channel) -> None:
        # Logger is configured by setup_logging called in serve()
        self.logger = logging.getLogger(__name__)
        self.logger.info("MDLEngineServicer initialized.")
        if document_signer_channel:
            self.document_signer_stub = document_signer_pb2_grpc.DocumentSignerStub(
                document_signer_channel
            )
            self.logger.info("DocumentSigner stub initialized.")
        else:
            self.document_signer_stub = None
            self.logger.warning(
                "DocumentSigner channel not provided. " "Document signing will not be available."
            )
        # Attempt to load a font for image generation
        self.font = None
        try:
            font_path = os.environ.get("DEFAULT_FONT_PATH", DEFAULT_FONT_PATH)
            font_size = int(os.environ.get("DEFAULT_FONT_SIZE", DEFAULT_FONT_SIZE))
            if os.path.exists(font_path):
                self.font = ImageFont.truetype(font_path, font_size)
                self.logger.info(f"Font loaded from {font_path}")
            else:
                self.logger.warning(
                    f"Font file not found at {font_path}. " "Text on MDL may not render."
                )
        except Exception as e:
            self.logger.error(f"Error loading font: {e}", exc_info=True)

    def _generate_qr_code(self, data: str, image_format: str = "PNG") -> bytes:
        self.logger.info(f"Generating QR code for data (first 30 chars): {data[:30]}...")
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.ERROR_CORRECT_H,  # Corrected constant
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        # make_image returns a PIL Image object by default if Pillow is installed
        # Force use of PilImage factory to ensure it's a PIL image.
        img = qr.make_image(fill_color="black", back_color="white", image_factory=PilImage)

        img_byte_arr = io.BytesIO()
        effective_format = image_format.upper()

        # Ensure image is in a mode compatible with the target format
        # PIL Image objects have a 'mode' attribute
        if effective_format == "JPEG":
            if img.mode in ("RGBA", "P"):
                img = img.convert("RGB")  # PIL Image convert method
        elif effective_format == "PNG":
            # qrcode default image mode might be '1' or 'L'.
            # PNG supports these, but converting to 'RGB' or 'RGBA' can be safer
            # for broader compatibility with viewers/processors.
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")  # Convert to RGB for consistency

        # PIL Image save method takes 'format' as a keyword argument
        img.save(img_byte_arr, format=effective_format)
        self.logger.info(f"QR code generated successfully, format: {effective_format}.")
        return img_byte_arr.getvalue()

    def _create_mdl_image(self, mdl_details: dict) -> bytes:
        self.logger.info("Creating mDL image representation...")
        try:
            width, height = 400, 250
            img = Image.new("RGB", (width, height), color=(255, 255, 255))
            d = ImageDraw.Draw(img)

            line_y = 10
            font_to_use = self.font

            if not font_to_use:
                try:
                    self.logger.info(
                        "User-specified font not available or failed to load. "
                        "Attempting to load default PIL font."
                    )
                    font_to_use = ImageFont.load_default()
                except Exception as font_e:
                    self.logger.exception(
                        f"Could not load default PIL font: {font_e}. "
                        "Text may not be rendered on mDL image."
                    )
                    # font_to_use remains None

            font_line_height = DEFAULT_FONT_SIZE + 5  # Default spacing
            if font_to_use:
                try:
                    # Get height of a character like 'A' or 'y' for line spacing
                    bbox = font_to_use.getbbox("Ay")
                    font_line_height = (bbox[3] - bbox[1]) + 5  # height + padding
                except AttributeError:  # Fallback for older PIL or unexpected font object
                    self.logger.warning("Could not get font bbox, using default line height.")
                except Exception as e:
                    self.logger.exception(
                        f"Error getting font metrics: {e}, using default line height."
                    )

            text_lines = [
                f"mDL Document ID: {mdl_details.get('document_id', 'N/A')}",
                f"User ID: {mdl_details.get('user_id', 'N/A')}",
                f"Issued: {mdl_details.get('issue_date', 'N/A')}",
                f"Expires: {mdl_details.get('expiry_date', 'N/A')}",
            ]

            for text_line in text_lines:
                if font_to_use:
                    try:
                        # Use textbbox for width calculation (more accurate)
                        text_bbox = d.textbbox((0, 0), text_line, font=font_to_use)
                        text_width = text_bbox[2] - text_bbox[0]

                        # Basic check for text overflow
                        if text_width > (width - 20):  # 10px padding each side
                            self.logger.warning(
                                f"Text line may be too wide for image: '{text_line[:40]}...'"
                            )
                        d.text((10, line_y), text_line, fill=(0, 0, 0), font=font_to_use)
                    except Exception as draw_e:
                        self.logger.exception(f"Error drawing text with loaded font: {draw_e}")
                        # Fallback to drawing without specific font if error occurs
                        d.text((10, line_y), text_line, fill=(0, 0, 0))
                else:
                    # Fallback if no font is available at all (draws very basic text)
                    d.text((10, line_y), text_line, fill=(0, 0, 0))
                line_y += font_line_height

            img_byte_arr = io.BytesIO()
            img.save(img_byte_arr, format="PNG")  # Save PIL image
            self.logger.info("mDL image representation created.")
            return img_byte_arr.getvalue()
        except Exception as e:
            self.logger.error(f"Error creating mDL image: {e}", exc_info=True)
            return b""

    def CreateMDL(self, request, context):
        self.logger.info(f"CreateMDL request received for user ID: {request.user_id}")
        try:
            document_id = str(uuid.uuid4())
            issue_date = datetime.now(timezone.utc)
            expiry_date = issue_date + timedelta(days=365)

            issue_date_iso = issue_date.isoformat()
            expiry_date_iso = expiry_date.isoformat()

            mdl_details = {
                "user_id": request.user_id,
                "document_id": document_id,
                "first_name": request.first_name,
                "last_name": request.last_name,
                "date_of_birth": request.date_of_birth,
                "issue_date": issue_date_iso,
                "expiry_date": expiry_date_iso,
                "portrait_image_url": request.portrait_image_url,
                "address": request.address,
                "vehicle_categories": list(request.vehicle_categories),
            }
            mdl_data_json = json.dumps(mdl_details)

            qr_content = f"MDL_DOC_ID:{document_id}"
            qr_code_bytes = self._generate_qr_code(qr_content)
            self.logger.info(f"QR code generated for document ID: {document_id}")

            mdl_image_bytes = self._create_mdl_image(mdl_details)

            signature = b""
            if self.document_signer_stub:
                self.logger.info("Attempting to sign MDL data (JSON).")
                try:
                    # Ensure document_signer_pb2 is imported for this type
                    sign_request = document_signer_pb2.SignDocumentRequest(
                        data_to_sign=mdl_data_json.encode("utf-8"),
                        # key_id="mdl_signing_key" # Optional
                    )
                    sign_response = self.document_signer_stub.SignDocument(sign_request)
                    signature = sign_response.signature
                    self.logger.info("MDL data signed successfully.")
                except grpc.RpcError as rpc_e:  # Ensure grpc is imported
                    # Access code and details as methods
                    status_code = rpc_e.code()
                    details = rpc_e.details()
                    self.logger.error(
                        f"gRPC error signing document: {status_code} - {details}", exc_info=True
                    )
                except Exception as e:
                    self.logger.error(f"Error during document signing: {e}", exc_info=True)
            else:
                self.logger.warning("DocumentSigner stub not available. Skipping signature.")

            # Ensure mdl_engine_pb2 is imported for this type
            return mdl_engine_pb2.CreateMDLResponse(
                mdl_id=document_id,
                qr_code=qr_code_bytes,
                signature=signature,
                mdl_image=mdl_image_bytes,
                status_message="MDL created successfully.",
            )
        except Exception as e:
            self.logger.error(f"Error creating MDL: {e}", exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)  # Ensure grpc is imported
            context.set_details(f"Internal server error: {e}")
            return mdl_engine_pb2.CreateMDLResponse(  # Ensure this is correct
                status_message=f"Error: {e}"
            )

    def VerifyMDL(self, request, context):
        self.logger.info(f"VerifyMDL request received for MDL ID: {request.mdl_id}")
        is_valid = True
        verification_details = "MDL verified (dummy)."

        if not request.mdl_id:
            self.logger.warning("VerifyMDL called with empty mdl_id.")
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)  # Ensure grpc is imported
            context.set_details("mdl_id cannot be empty.")
            return mdl_engine_pb2.VerifyMDLResponse(  # Ensure this is correct
                is_valid=False, verification_details="Invalid request: mdl_id missing."
            )

        self.logger.info(f"Verification result for {request.mdl_id}: {is_valid}")
        return mdl_engine_pb2.VerifyMDLResponse(  # Ensure this is correct
            is_valid=is_valid, verification_details=verification_details
        )


def serve() -> None:
    global logger

    service_name = os.environ.get("MDL_ENGINE_SERVICE_NAME", "mdl-engine")
    # Setup logging FIRST, so all subsequent loggers get this configuration.
    setup_logging(service_name=service_name)
    # Now, initialize the module-level logger.
    logger = logging.getLogger(__name__)

    logger.info(f"Starting {service_name} gRPC server...")

    grpc_port = os.environ.get("GRPC_PORT", "50051")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))

    document_signer_host = os.environ.get("DOCUMENT_SIGNER_HOST", "document-signer")
    document_signer_port = os.environ.get("DOCUMENT_SIGNER_PORT", "8082")
    document_signer_channel = None
    if document_signer_host and document_signer_port:
        ds_address = f"{document_signer_host}:{document_signer_port}"
        try:
            document_signer_channel = grpc.insecure_channel(ds_address)
            logger.info(f"Created channel to DocumentSigner at {ds_address}")
        except Exception as e:
            logger.error(
                f"Failed to create channel to DocumentSigner at {ds_address}: {e}", exc_info=True
            )
    else:
        logger.warning(
            "DocumentSigner host/port not configured. " "Document signing will be unavailable."
        )

    servicer_instance = MDLEngineServicer(document_signer_channel)
    # Ensure mdl_engine_pb2_grpc is imported for this function
    mdl_engine_pb2_grpc.add_MDLEngineServicer_to_server(servicer_instance, server)
    logger.info("MDLEngineServicer added to gRPC server.")

    try:
        logging_streamer_servicer = LoggingStreamerServicer()
        # Ensure common_services_pb2_grpc is imported for this function
        common_services_pb2_grpc.add_LoggingStreamerServicer_to_server(
            logging_streamer_servicer, server
        )
        logger.info("Successfully added LoggingStreamerServicer to gRPC server.")
    except AttributeError as ae:
        logger.error(
            f"Failed to add LoggingStreamerServicer due to AttributeError: {ae}. "
            "Ensure 'common_services.proto' is compiled and "
            "'common_services_pb2_grpc.py' is correctly generated and importable.",
            exc_info=True,
        )
    except Exception as e:
        logger.error(f"Failed to add LoggingStreamerServicer: {e}", exc_info=True)

    server.add_insecure_port(f"[::]:{grpc_port}")
    server.start()
    logger.info(f"{service_name} server started successfully on port {grpc_port}.")

    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        logger.info("Shutting down server due to KeyboardInterrupt...")
    except Exception as e:
        logger.error(f"Server termination error: {e}", exc_info=True)
    finally:
        logger.info("Stopping gRPC server...")
        server.stop(0)
        logger.info(f"{service_name} server shut down.")


if __name__ == "__main__":
    # This debug print helps confirm standalone execution context
    print(
        f"DEBUG: mdl_engine.py execution started. "
        f"SERVICE_NAME='{os.environ.get('MDL_ENGINE_SERVICE_NAME', 'mdl-engine-default')}', "
        f"GRPC_PORT='{os.environ.get('GRPC_PORT', '50051')}'",
        file=sys.stdout,  # Explicitly use sys.stdout for clarity
    )
    sys.stdout.flush()  # Ensure debug output is seen immediately
    serve()
