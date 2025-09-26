"""Shared helpers & selectors for Playwright E2E tests.

Provides stable selector indirection so template changes require minimal test edits.
"""
from __future__ import annotations

from playwright.async_api import Locator, Page

# Core selectors mapped semantically to reduce brittleness
SELECTORS = {
    "passport.process.form": "form[action='/passport/process']",
    "passport.process.input": "#passport_number",
    "passport.inspect.form": "form[action='/passport/inspect']",
    "passport.inspect.input": "#inspect_passport_number",
    "result.panel": ".result-panel",
    "status.badge": (
        ".result-panel .status-success, .result-panel .status-warning, "
        ".result-panel .status-error, .result-panel [class*='status-']"
    ),
    "mdl.create.form": "form[action='/mdl/create']",
    "mdl.create.license": "#license_number",
    "mdl.create.first_name": "#first_name",
    "mdl.create.last_name": "#last_name",
    "mdl.lookup.form": "form[action='/mdl/lookup'], form[action='/mdl/search']",
    "csca.create.form": "form[action='/csca/create']",
    "csca.create.country": "#country",
    "csca.create.organization": "#organization",
    "trust.validate.form": "form[action='/trust-anchor/validate']",
    "pkd.sync.form": "form[action='/pkd/sync']",
    "activity.list": ".activity-list li, .recent-activity li, .operation-log li",
    "dashboard.cards": ".card, .dashboard-card, .service-card",
    "nav.menu": "nav a, .nav a, .navigation a, .menu a, [role='navigation'] a",
    "health.indicator": ".health, .status, .system-status, [class*='health'], [class*='status']",
}


def sel(name: str) -> str:  # small helper, inline access
    return SELECTORS[name]


def first(page: Page, name: str) -> Locator:
    return page.locator(sel(name)).first


async def panel_text(page: Page) -> str:
    panels = page.locator(sel("result.panel"))
    if await panels.count() > 0:  # async-safe count
        return await panels.first.inner_text()
    return ""
