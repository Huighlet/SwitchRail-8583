"""
End-to-End API, SQLite WAL Persistence, and Playwright Visual Verification Tests for SwitchRail-8583.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from starlette.testclient import TestClient

from switchrail.server import SwitchPersistence, app


EMOJI_REGEX = re.compile(
    "["
    "\U0001F300-\U0001F9FF"
    "\U00002600-\U000027BF"
    "\U0001FA00-\U0001FAFF"
    "]+",
    flags=re.UNICODE,
)


def _assert_clean_institutional_text(text: str) -> None:
    assert "undefined" not in text.lower(), "Found 'undefined' in rendered UI text"
    assert "nan" not in re.findall(r"\bnan\b", text.lower()), "Found 'NaN' in rendered UI text"
    emojis = EMOJI_REGEX.findall(text)
    assert not emojis, f"Found forbidden unicode emojis: {emojis}"


def test_switch_state_and_sqlite_persistence(tmp_path: Path):
    db_file = str(tmp_path / "test_switchrail.db")
    store = SwitchPersistence(db_path=db_file)
    assert os.path.exists(db_file)

    client = TestClient(app)
    state_resp = client.get("/v1/switch/state")
    assert state_resp.status_code == 200
    state = state_resp.json()
    assert state["status"] == "ONLINE"
    assert state["db_engine"] == "SQLite3 WAL"
    assert "telemetry" in state
    assert "routes" in state
    assert "journal" in state
    assert "saf_queue" in state


def test_bootstrap_and_saf_drain_endpoints():
    client = TestClient(app)

    boot_resp = client.post("/v1/switch/bootstrap")
    assert boot_resp.status_code == 200
    boot_data = boot_resp.json()
    assert boot_data["seeded"] is True
    assert boot_data["seeded_transactions"] >= 7

    state = boot_data["state"]
    assert state["telemetry"]["processed_count"] >= 7
    assert state["telemetry"]["reversals_count"] >= 1
    assert len(state["saf_queue"]) >= 1

    drain_resp = client.post("/v1/switch/saf/drain")
    assert drain_resp.status_code == 200
    drain_data = drain_resp.json()
    assert drain_data["status"] == "DRAINED"
    assert drain_data["remaining_pending"] == 0


def test_lpm_route_match_endpoint():
    client = TestClient(app)

    resp_eco = client.post("/v1/routes/match", json={"pan": "4143450089123456"})
    assert resp_eco.status_code == 200
    d_eco = resp_eco.json()
    assert d_eco["destination_id"] == "ECOBANK_GH"
    assert d_eco["matched_prefix"] == "414345"
    assert d_eco["is_default_fallback"] is False

    resp_def = client.post("/v1/routes/match", json={"pan": "6061050011223344"})
    assert resp_def.status_code == 200
    d_def = resp_def.json()
    assert d_def["destination_id"] == "GHIPSS_NATIONAL_SWITCH"
    assert d_def["is_default_fallback"] is True


def _wait_for_server(url: str, timeout_s: float = 10.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = httpx.get(url, timeout=1.0)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.15)
    raise RuntimeError(f"Server at {url} did not become ready within {timeout_s}s")


def test_visual_operator_console_e2e(tmp_path: Path):
    """
    Start a live FastAPI server on port 8584 in a separate process against a fresh
    SQLite WAL database, exercise all 4 operator console tabs via Playwright,
    verify zero emojis and zero undefined values, and capture 4 documentation screenshots.
    """
    import subprocess
    import sys

    from playwright.sync_api import sync_playwright

    repo_root = Path(__file__).resolve().parent.parent
    screenshots_dir = repo_root / "docs" / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    port = 8584
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    env["SWITCHRAIL_DB_PATH"] = str(tmp_path / "switchrail_visual_e2e.db")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "switchrail.server:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(repo_root),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    base_url = f"http://127.0.0.1:{port}"
    _wait_for_server(f"{base_url}/health", timeout_s=20.0)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(viewport={"width": 1440, "height": 940})
            page = context.new_page()

            page.goto(base_url, wait_until="domcontentloaded")
            page.wait_for_selector("#sim-bitmap-grid .bit-cell.active")

            # Seed live multi-bank network traffic
            page.click("#btn-seed-traffic")
            page.wait_for_selector('#btn-seed-traffic[data-seeded="true"]', timeout=10000)

            # 1. Tab 1: Live ISO 8583 Terminal & POS Simulator
            page.click("#tab-btn-simulator")
            page.click("#btn-dispatch-tx")
            page.wait_for_timeout(200)

            active_bits_count = page.locator("#sim-bitmap-grid .bit-cell.active").count()
            assert active_bits_count >= 11, f"Expected >= 11 active bitmap bits, got {active_bits_count}"

            body_text_1 = page.inner_text("body")
            _assert_clean_institutional_text(body_text_1)
            assert "ECOBANK_GH" in body_text_1
            assert "0210" in body_text_1

            shot_1 = screenshots_dir / "switchrail_01_pos_terminal_bitmap.png"
            page.screenshot(path=str(shot_1), full_page=False)
            assert shot_1.exists() and shot_1.stat().st_size > 10_000

            # 2. Tab 2: Wire Frame Hex Dissector
            page.click("#tab-btn-dissector")
            page.click("#btn-sample-0420")
            page.wait_for_selector('#dissector-mti-badge:has-text("MTI: 0420")', timeout=5000)

            dissector_bits = page.locator("#dissector-bitmap-grid .bit-cell").count()
            assert dissector_bits == 128, f"Expected 128-bit secondary bitmap for 0420 DE 90 frame, got {dissector_bits}"

            body_text_2 = page.inner_text("body")
            _assert_clean_institutional_text(body_text_2)
            assert "DE 90" in body_text_2

            shot_2 = screenshots_dir / "switchrail_02_hex_frame_dissector.png"
            page.screenshot(path=str(shot_2), full_page=False)
            assert shot_2.exists() and shot_2.stat().st_size > 10_000

            # 3. Tab 3: LPM BIN Routing Table
            page.click("#tab-btn-routing")
            page.wait_for_timeout(200)
            page.click("#btn-add-route")
            page.wait_for_timeout(300)

            body_text_3 = page.inner_text("body")
            _assert_clean_institutional_text(body_text_3)
            assert "FIDELITY_BANK_GH" in body_text_3
            assert "LPM WINNER" in body_text_3

            shot_3 = screenshots_dir / "switchrail_03_lpm_bin_routing.png"
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(150)
            page.screenshot(path=str(shot_3), full_page=False)
            assert shot_3.exists() and shot_3.stat().st_size > 10_000

            # 4. Tab 4: 0420 SAF Reversal Queue & Settlement Journal
            page.click("#tab-btn-saf")
            page.wait_for_timeout(250)

            rev_buttons = page.locator(".btn-trigger-reversal")
            if rev_buttons.count() > 0:
                rev_buttons.first.click()
                page.wait_for_timeout(300)

            page.click("#btn-drain-saf")
            page.wait_for_timeout(300)
            page.click("#btn-run-eod")
            page.wait_for_timeout(300)

            body_text_4 = page.inner_text("body")
            _assert_clean_institutional_text(body_text_4)
            assert "SETTLED_0430_ACK" in body_text_4
            assert "REVERSED" in body_text_4

            shot_4 = screenshots_dir / "switchrail_04_saf_reversal_journal.png"
            page.screenshot(path=str(shot_4), full_page=False)
            assert shot_4.exists() and shot_4.stat().st_size > 10_000

            browser.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
