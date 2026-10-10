import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.honeypot import run_honeypot_chat_turn
from app.schemas.common import IndicatorTypeEnum

client = TestClient(app)

def test_phase6_honeypot_two_turns_demonstration():
    # Turn 1: Initial scammer message
    turn1_payload = {
        "message": "Urgent! Pay $50 fine to support@ybl or your account will be closed immediately.",
        "persona": "victim"
    }
    res1 = client.post("/api/chat", json=turn1_payload)
    assert res1.status_code == 200
    data1 = res1.json()

    session_id = data1["session_id"]
    assert data1["turn_count"] == 1
    assert data1["persona"] == "victim"
    assert "reply" in data1 and len(data1["reply"]) > 0
    assert "safety_note" in data1 and "SIMULATION ONLY" in data1["safety_note"]
    assert len(data1["extracted_iocs"]) >= 1
    assert data1["extracted_iocs"][0]["type"] == IndicatorTypeEnum.UPI.value

    # Turn 2: Follow-up scammer message in same session
    turn2_payload = {
        "session_id": session_id,
        "message": "Why haven't you paid yet? Send 0.1 BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa now!",
        "persona": "victim"
    }
    res2 = client.post("/api/chat", json=turn2_payload)
    assert res2.status_code == 200
    data2 = res2.json()

    assert data2["session_id"] == session_id
    assert data2["turn_count"] == 2
    assert "safety_note" in data2
    assert len(data2["extracted_iocs"]) >= 1
    assert any(i["type"] == IndicatorTypeEnum.CRYPTO.value for i in data2["extracted_iocs"])

def test_phase6_confused_user_persona():
    payload = {
        "message": "Visit http://phish-login.xyz to verify your credentials.",
        "persona": "confused_user"
    }
    res = client.post("/api/chat", json=payload)
    assert res.status_code == 200
    data = res.json()

    assert data["persona"] == "confused_user"
    assert data["turn_count"] == 1
    assert "safety_note" in data
    assert len(data["extracted_iocs"]) >= 1

def test_phase6_no_external_messages_safety():
    # Verify safety note guarantees isolated sandbox execution
    payload = {
        "message": "Send money to 9876543210 immediately!",
        "persona": "victim"
    }
    res = client.post("/api/chat", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "safety_note" in data
    assert "isolated sandbox" in data["safety_note"].lower()
