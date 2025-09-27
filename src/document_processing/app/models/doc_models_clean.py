"""Clean Pydantic models for the Document Processing API.

Temporary file to bypass corrupted legacy `document_models.py`.
All consuming code should import from this module instead of `document_models`.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class CheckResult(int, Enum):
    NEGATIVE = 0
    POSITIVE = 1
    NOT_PERFORMED = 2

class ProcessingStatus(int, Enum):
    NOT_FINISHED = 0
    FINISHED = 1
    TIMEOUT = 2

class RfidLocation(int, Enum):
    NO_CHIP = 0
    DATA_PAGE = 1
    BACK_PAGE = 2

class ContainerType(str, Enum):
    MRZ_CONTAINER = "MrzContainer"
    IMAGE_QUALITY_CONTAINER = "ImageQualityContainer"
    LOG_CONTAINER = "LogContainer"

class Light(int, Enum):
    OFF = 0
    VISIBLE = 1
    UV = 2
    IR = 6

class ErrorResponse(BaseModel):
    code: str
    message: str
    details: Optional[dict[str, Any]] = None

class HealthResponse(BaseModel):
    status: str = "ready"
    version: str
    uptimeSec: int
    license: Optional[dict[str, Any]] = None

class LicenseInfo(BaseModel):
    valid: bool
    expiresAt: str

class TransactionInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    # Accept either camelCase or alias names on input; always expose camelCase attributes
    requestId: str = Field(..., alias="TransactionID")
    createdAt: str = Field(..., alias="DateTime")
    coreVersion: str
    computerName: Optional[str] = Field(None, alias="ComputerName")
    userName: Optional[str] = Field(None, alias="UserName")

class ImageQualityThresholds(BaseModel):
    minFocus: Optional[int] = Field(None, ge=0, le=100)
    maxGlare: Optional[int] = Field(None, ge=0, le=100)
    minDpi: Optional[int] = Field(None, ge=72)
    maxAngle: Optional[int] = Field(None, ge=0, le=90)
    brightnessThreshold: Optional[int] = None
    dpiThreshold: Optional[int] = None
    angleThreshold: Optional[int] = None
    focusCheck: Optional[bool] = None
    glaresCheck: Optional[bool] = None
    colornessCheck: Optional[bool] = None
    moireCheck: Optional[bool] = None
    documentPositionIndent: Optional[int] = None
    expectedPass: Optional[list[str]] = None

class ImageQualityReport(BaseModel):
    focus: int
    glare: int
    dpi: int
    angle: int
    passed: bool
    failedReasons: Optional[list[str]] = None

class ProcessParam(BaseModel):
    scenario: str
    resultTypeOutput: Optional[list[str]] = None
    mrzFormatsFilter: Optional[list[str]] = None
    strictImageQuality: Optional[bool] = False
    imageQa: Optional[ImageQualityThresholds] = None
    forceReadMrzBeforeLocate: Optional[bool] = False
    dateFormat: Optional[str] = "MM/dd/yyyy"
    log: Optional[bool] = True
    logLevel: Optional[str] = "FatalError"
    generateNumericCodes: Optional[bool] = True
    generateAlpha2Codes: Optional[bool] = True

class ProcessRequestImage(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    ImageData: Optional[str] = None
    ImageUri: Optional[str] = None
    pageIdx: Optional[int] = Field(None, alias="page_idx")
    light: Optional[Light] = Light.VISIBLE

class ProcessRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    processParam: ProcessParam
    images: list[ProcessRequestImage] = Field(..., alias="List", min_length=1)
    tag: Optional[str] = None

    # Backwards compatibility accessor
    @property
    def List(self) -> list[ProcessRequestImage]:  # noqa: N802 (preserve external contract)
        return self.images

class MRZField(BaseModel):
    name: str
    value: str
    confidence: Optional[float] = None
    line: Optional[int] = None
    start: Optional[int] = None
    length: Optional[int] = None
    checksumValid: Optional[bool] = None
    warnings: Optional[list[str]] = None

class MRZResult(BaseModel):
    docType: Optional[str] = None
    issuingState: Optional[str] = None
    nationality: Optional[str] = None
    documentNumber: Optional[str] = None
    documentNumberChecksumValid: Optional[bool] = None
    optionalData: Optional[str] = None
    givenNames: Optional[str] = None
    surname: Optional[str] = None
    dateOfBirth: Optional[str] = None
    dateOfBirthChecksumValid: Optional[bool] = None
    sex: Optional[str] = None
    dateOfExpiry: Optional[str] = None
    dateOfExpiryChecksumValid: Optional[bool] = None
    mrzLines: Optional[list[str]] = None
    overallValid: Optional[bool] = None
    fields: Optional[list[MRZField]] = None

class Status(BaseModel):
    overallStatus: CheckResult
    optical: CheckResult
    portrait: CheckResult
    rfid: CheckResult
    stopList: CheckResult

class Container(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    type: ContainerType
    buf_length: Optional[int] = None
    light: Optional[int] = None
    list_idx: Optional[int] = None
    page_idx: Optional[int] = None
    result_type: Optional[int] = None
    # Use snake_case internally but keep legacy 'Status' alias for compatibility
    status: Optional[Status] = Field(None, alias="Status")
    mrzResult: Optional[MRZResult] = None
    imageQuality: Optional[ImageQualityReport] = None
    logs: Optional[list[str]] = None

class ContainerList(BaseModel):
    Count: int
    List: list[Container]

class ProcessResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    transactionInfo: Optional[TransactionInfo] = Field(None, alias="TransactionInfo")
    elapsedTime: int
    containerList: Optional[ContainerList] = Field(None, alias="ContainerList")
    ChipPage: RfidLocation = RfidLocation.NO_CHIP
    CoreLibResultCode: int = 0
    ProcessingFinished: ProcessingStatus = ProcessingStatus.FINISHED
    log: Optional[str] = None
    passBackObject: Optional[dict[str, Any]] = None
    morePagesAvailable: int = 0
    metadata: Optional[dict[str, Any]] = None

ImageQualityThresholds.model_rebuild()
ImageQualityReport.model_rebuild()
ProcessParam.model_rebuild()
ProcessRequestImage.model_rebuild()
ProcessRequest.model_rebuild()
MRZField.model_rebuild()
MRZResult.model_rebuild()
Status.model_rebuild()
Container.model_rebuild()
ContainerList.model_rebuild()
TransactionInfo.model_rebuild()
ProcessResponse.model_rebuild()

__all__ = [
    "CheckResult",
    "Container",
    "ContainerList",
    "ContainerType",
    "ErrorResponse",
    "HealthResponse",
    "ImageQualityReport",
    "ImageQualityThresholds",
    "LicenseInfo",
    "Light",
    "MRZField",
    "MRZResult",
    "ProcessParam",
    "ProcessRequest",
    "ProcessRequestImage",
    "ProcessResponse",
    "ProcessingStatus",
    "RfidLocation",
    "Status",
    "TransactionInfo",
]
