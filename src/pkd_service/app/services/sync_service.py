"""
Service for handling PKD synchronization operations
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Optional

from app.models.pkd_models import (
    ComponentSyncStatus,
    PkdSyncRequest,
    PkdSyncResponse,
    PkdSyncStatusResponse,
    SyncStatus,
)

logger = logging.getLogger(__name__)


class SyncService:
    """Service for managing PKD synchronization"""

    # In a real implementation, this would be stored in a database
    # For this example, we'll use in-memory storage
    _sync_jobs: dict[str, PkdSyncStatusResponse] = {}

    async def initiate_sync(self, request: PkdSyncRequest) -> PkdSyncResponse:
        """
        Initiate synchronization with an external PKD.

        In a real implementation, this would start a background task that fetches
        data from the external PKD and updates local storage.
        """
        sync_id = str(uuid.uuid4())
        now = datetime.now()

        # Create a sync status object
        status = PkdSyncStatusResponse(
            id=sync_id,
            status=SyncStatus.INITIATED,
            start_time=now,
            components={component: ComponentSyncStatus.PENDING for component in request.components},
        )

        # Store the status
        self._sync_jobs[sync_id] = status

        # In a real implementation, start a background task
        asyncio.create_task(self._perform_sync(sync_id, request))

        # Return the initial response
        return PkdSyncResponse(id=sync_id, status=SyncStatus.INITIATED, start_time=now)

    async def get_sync_status(self, sync_id: Optional[str] = None) -> PkdSyncStatusResponse:
        """
        Get the status of a PKD synchronization job.

        If no sync_id is provided, returns the status of the most recent job.
        """
        if not self._sync_jobs:
            # No sync jobs yet
            return PkdSyncStatusResponse(
                id="00000000-0000-0000-0000-000000000000", status=SyncStatus.NOT_STARTED
            )

        if sync_id is None:
            # Return the most recent job
            # In a real implementation, sort by start_time
            sync_id = list(self._sync_jobs.keys())[-1]

        if sync_id not in self._sync_jobs:
            msg = f"Sync job with ID {sync_id} not found"
            raise ValueError(msg)

        return self._sync_jobs[sync_id]

    async def _perform_sync(self, sync_id: str, request: PkdSyncRequest) -> None:
        """
        Background task to perform synchronization.

        In a real implementation, this would connect to the external PKD,
        download the requested components, and update local storage.
        """
        if sync_id not in self._sync_jobs:
            logger.error(f"Sync job with ID {sync_id} not found")
            return

        # Update status to in progress
        self._sync_jobs[sync_id].status = SyncStatus.IN_PROGRESS

        # Process each component
        for component in request.components:
            try:
                # Update component status
                self._sync_jobs[sync_id].components[component] = ComponentSyncStatus.IN_PROGRESS

                # Simulate processing time
                await asyncio.sleep(1)

                # In a real implementation, download and process the component
                logger.info(f"Synchronizing {component} from {request.sync_source}")

                # Update component status to completed
                self._sync_jobs[sync_id].components[component] = ComponentSyncStatus.COMPLETED

            except Exception as e:
                logger.exception(f"Failed to sync {component}: {e!s}")
                self._sync_jobs[sync_id].components[component] = ComponentSyncStatus.FAILED
                self._sync_jobs[sync_id].error_message = f"Failed to sync {component}: {e!s}"

        # Update overall status
        if all(
            status == ComponentSyncStatus.COMPLETED
            for status in self._sync_jobs[sync_id].components.values()
        ):
            self._sync_jobs[sync_id].status = SyncStatus.COMPLETED
        elif any(
            status == ComponentSyncStatus.FAILED
            for status in self._sync_jobs[sync_id].components.values()
        ):
            self._sync_jobs[sync_id].status = SyncStatus.FAILED

        # Set end time
        self._sync_jobs[sync_id].end_time = datetime.now()
