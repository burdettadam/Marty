# Marty UI/UX Design Overview

## Design Principles
- **Operational transparency:** expose critical lifecycle states (issuance, signing, verification) with clear status cues
- **Service orchestration:** allow operators to trigger cross-service workflows without memorising gRPC details
- **Auditability:** capture who triggered actions and surface system log links for investigations
- **Environment awareness:** prominently display target environment and service endpoints to avoid mistakes

## Primary Personas
1. **Credential Operations Engineer** – provisions passports and mobile credentials, monitors certificate health
2. **Verification Analyst** – validates document authenticity, reviews inspection results
3. **PKI Administrator** – manages trust anchors, monitors certificate rotations and expirations

## UX Flows

### 1. Passport Issuance & Verification
1. Operator lands on dashboard, sees "Passport Operations" card with quick actions
2. Click "Process Passport" → form requests optional passport number; displays target Passport Engine endpoint
3. On submit, UI calls Passport Engine `ProcessPassport`, stores response in session history
4. Success view shows status badge, generated passport number, link to inspection step
5. "Verify Passport" button opens modal (or secondary page) to inspect via Inspection System `Inspect`
6. Inspection results rendered with validity banner; show issue/expiry dates and data-group count
7. Session history table keeps recent operations with timestamps for audit/replay

### 2. Mobile Driving Licence (MDL) Lifecycle
1. Dashboard card summarises pending MDL signatures and latest activity
2. "Create MDL" form captures user/driver metadata, license categories, additional fields (dynamic inputs)
3. Submit triggers MDL service `CreateMDL`; success view links to detail page
4. Detail page fetches MDL via `GetMDL`, showing status timeline (Draft → Pending Signature → Signed)
5. Actions panel: request signature (future), download QR (future), transfer to device (future)
6. Inline alerts guide operator if status blocks next steps

### 3. Trust Anchor Management
1. Trust anchor card shows counts of trusted vs revoked entities
2. Listing table reads trust store via new REST/gRPC bridge (to be implemented) and flags revoked items
3. Inline action toggles trust state with confirmation modal; updates via `update_trust_store`
4. Provide journal modal showing latest changes (pulled from audit log or simulated data)

### 4. Observability & Diagnostics
1. Dashboard header surfaces environment, database connection, and aggregated health status (via gRPC health checks)
2. "Service Status" view lists each gRPC service, last heartbeat, and quick link to tail logs (leveraging LoggingStreamer)
3. Log streaming page opens websocket stream to LoggingStreamer and filters by service, severity
4. Provide download option for log snippet (client-side)

### Navigation Structure
- **Dashboard:** overview cards, recent activity log
- **Passports:** tabs for "Issue" and "Verify"
- **MDL:** tabs for "Create" and "Lookup"
- **Trust & Certificates:** trust anchor grid, certificate lifecycle monitor summary
- **System Health:** service health, log streaming

## Screen Wireframes (Textual)
- **Dashboard Card Layout:** three cards in responsive grid (Passports, MDL, Trust). Each card: title, KPI, primary CTA, secondary CTA link
- **Form Layouts:** two-column forms for desktop, collapsible accordions for advanced options (e.g., additional MDL fields)
- **Result Panels:** status badge (green=Success, yellow=Pending, red=Error) with metadata list and contextual actions on the right
- **History Table:** columns for timestamp, action, identifier, status; sortable and filterable

## Future Enhancements
- Embed PKI visualisation (certificate chains) for trust anchor admins
- Add role-based access with fine-grained permissions per action
- Internationalise UI labels for deployment in multilingual environments
- Provide offline-ready inspector view for border-agent tablets

