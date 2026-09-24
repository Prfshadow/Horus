import json
import pytest
from app.ai.validators import validate_investigation_analysis, extract_json

def test_valid_response():
    raw = json.dumps({
        "summary": "summary text",
        "observations": [
            {"statement": "fact observed", "type": "fact", "evidence_ids": ["incident:1"]},
            {"statement": "inference", "type": "inference", "evidence_ids": ["event:101"], "confidence": "medium"},
            {"statement": "uncertain", "type": "uncertainty", "evidence_ids": []}
        ],
        "supporting_evidence": ["incident:1"],
        "alternative_explanations": [{"explanation": "alt", "evidence_ids": []}],
        "recommended_steps": ["check logs"],
        "limitations": ["limited"]
    })
    allowed = {"incident:1", "event:101"}
    analysis = validate_investigation_analysis(raw, allowed)
    assert analysis.summary == "summary text"
    assert len(analysis.observations) == 3

def test_malformed_json():
    raw = "{ not json"
    try:
        validate_investigation_analysis(raw, set())
        assert False
    except ValueError as e:
        assert "Malformed JSON" in str(e)

def test_missing_field():
    raw = json.dumps({"summary": "s"})
    try:
        validate_investigation_analysis(raw, set())
        assert False
    except ValueError as e:
        assert "Schema validation" in str(e)

def test_invalid_enum():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"x","type":"invalid_type","evidence_ids":[]}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, set())
        assert False
    except ValueError:
        pass

def test_fact_without_evidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"fact","type":"fact","evidence_ids":[]}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, set())
        assert False
    except ValueError as e:
        assert "fact" in str(e).lower()

def test_inference_without_evidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"inf","type":"inference","evidence_ids":[],"confidence":"high"}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, set())
        assert False
    except ValueError as e:
        assert "inference" in str(e).lower()

def test_inference_without_confidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"inf","type":"inference","evidence_ids":["incident:1"]}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, {"incident:1"})
        assert False
    except ValueError as e:
        assert "confidence" in str(e).lower()

def test_fact_with_confidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"fact","type":"fact","evidence_ids":["incident:1"],"confidence":"high"}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, {"incident:1"})
        assert False
    except ValueError as e:
        assert "confidence" in str(e).lower()

def test_uncertainty_with_confidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"u","type":"uncertainty","evidence_ids":[],"confidence":"high"}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, {"incident:1"})
        assert False
    except ValueError:
        pass

def test_unknown_evidence_id():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"fact","type":"fact","evidence_ids":["event:999999"]}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, {"incident:1"})
        assert False
    except ValueError as e:
        assert "Unknown evidence" in str(e)

def test_hallucinated_supporting_evidence():
    raw = json.dumps({
        "summary": "s",
        "observations": [{"statement":"fact","type":"fact","evidence_ids":["incident:1"]}],
        "supporting_evidence": ["event:999"],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    })
    try:
        validate_investigation_analysis(raw, {"incident:1"})
        assert False
    except ValueError as e:
        assert "Unknown" in str(e)

def test_extract_json_with_fence():
    raw = "```json\n{\"summary\":\"s\",\"observations\":[{\"statement\":\"fact\",\"type\":\"fact\",\"evidence_ids\":[\"incident:1\"]}],\"supporting_evidence\":[],\"alternative_explanations\":[],\"recommended_steps\":[],\"limitations\":[]}\n```"
    extracted = extract_json(raw)
    assert "summary" in extracted

def test_valid_with_fence():
    raw = "```json\n" + json.dumps({
        "summary": "s",
        "observations": [{"statement":"fact","type":"fact","evidence_ids":["incident:1"]}],
        "supporting_evidence": [],
        "alternative_explanations": [],
        "recommended_steps": [],
        "limitations": []
    }) + "\n```"
    analysis = validate_investigation_analysis(raw, {"incident:1"})
    assert analysis.summary == "s"
