"""Tests for the data-protection packs: packs/gdpr, packs/uk-gdpr, packs/jp-appi.

Expected values come from the legal text (EUR-Lex consolidated GDPR; UK GDPR on
legislation.gov.uk as of 2026-11-14; APPI on e-Gov as of 2026-11-14), not from the
packs: each test puts the facts on one side of a condition the text sets.
"""

from pathlib import Path

import pytest

from normir import Evaluator, Residual, amendment_status, load, validate
from normir.evaluate import facts_in
from normir.evidence import load_evidence, run

ROOT = Path(__file__).resolve().parents[1]
GDPR = ROOT / "packs" / "gdpr"
UK = ROOT / "packs" / "uk-gdpr"
APPI = ROOT / "packs" / "jp-appi"


def norm(pack, name, system=None, instance=None):
    return Evaluator(load(pack), system).norm(name, instance)


def open_facts(v):
    assert isinstance(v, Residual), v
    return facts_in(v.expr)


# ------------------------------------------------------------------ packages


@pytest.mark.parametrize("pack", [GDPR, UK, APPI])
def test_pack_validates(pack):
    errors, warnings = validate(load(pack))
    assert errors == []
    assert warnings == []


@pytest.mark.parametrize("pack", [GDPR, UK, APPI])
def test_every_element_is_draft_and_system_subject(pack):
    rs = load(pack)
    assert rs.subject == "system"
    assert all(el.data.get("status", "draft") == "draft" for el in rs.elements.values())


# ------------------------------------------------------------ GDPR Art. 17


def test_art17_no_personal_data_needs_no_erasure_path():
    # Art. 17(1) is about "personal data concerning him or her": nothing to erase.
    assert norm(GDPR, "art17_erasure_path", {"processes_personal_data": False, "account_erasure": False}) is True


def test_art17_personal_data_without_erasure_path_fails():
    assert norm(GDPR, "art17_erasure_path", {"processes_personal_data": True, "account_erasure": False}) is False


def test_art17_personal_data_with_erasure_path_passes():
    assert norm(GDPR, "art17_erasure_path", {"processes_personal_data": True, "account_erasure": True}) is True


def test_art17_lists_17_3_exceptions_as_deferred():
    el = load(GDPR).get("norm", "art17_erasure_path")
    assert any(d.startswith("Art. 17(3)") for d in el.data["defers_to"])


# ---------------------------------------------------- GDPR Art. 44, 45, 46

US_TRANSFER = {"recipient": "analytics.example.com", "personal_data": True, "third_country": True}


def test_gdpr_transfer_to_us_without_safeguards_fails():
    assert norm(GDPR, "chapter5_transfer_basis", instance={**US_TRANSFER, "adequacy_or_safeguards": False}) is False


def test_gdpr_transfer_to_us_with_safeguards_passes():
    assert norm(GDPR, "chapter5_transfer_basis", instance={**US_TRANSFER, "adequacy_or_safeguards": True}) is True


def test_gdpr_transfer_safeguards_unknown_is_not_a_fail():
    v = norm(GDPR, "chapter5_transfer_basis", instance=US_TRANSFER)
    assert open_facts(v) == ["Transfer.adequacy_or_safeguards"]


def test_gdpr_transfer_within_eea_or_without_personal_data_passes():
    # Art. 44 applies only to personal data sent to a third country.
    assert norm(GDPR, "chapter5_transfer_basis", instance={**US_TRANSFER, "third_country": False}) is True
    assert norm(GDPR, "chapter5_transfer_basis", instance={**US_TRANSFER, "personal_data": False}) is True


# ----------------------------------------------------------- GDPR Art. 32


def test_art32_md5_fails_and_argon2_passes():
    assert norm(GDPR, "art32_password_hashing", instance={"algorithm": "md5", "salted": True}) is False
    assert norm(GDPR, "art32_password_hashing", instance={"algorithm": "argon2", "salted": True}) is True


def test_art32_unsalted_slow_hash_fails():
    assert norm(GDPR, "art32_password_hashing", instance={"algorithm": "bcrypt", "salted": False}) is False


def test_art32_password_norm_is_marked_as_interpretation():
    interp = load(GDPR).get("norm", "art32_password_hashing").data["interpretation"]
    assert interp["by"] == "pack" and interp["authority"]


def test_art32_credentials_in_logs():
    assert norm(GDPR, "art32_no_credentials_in_logs", instance={"logs_credentials": True}) is False
    assert norm(GDPR, "art32_no_credentials_in_logs", instance={"logs_credentials": False}) is True


# ------------------------------------------------------------ GDPR Art. 20


def test_art20_personal_data_without_export_fails():
    assert norm(GDPR, "art20_data_export", {"processes_personal_data": True, "account_data_export": False}) is False


def test_art20_personal_data_with_export_passes():
    assert norm(GDPR, "art20_data_export", {"processes_personal_data": True, "account_data_export": True}) is True


def test_art20_no_personal_data_needs_no_export():
    # Art. 20(1): "the personal data concerning him or her": nothing to port.
    assert norm(GDPR, "art20_data_export", {"processes_personal_data": False, "account_data_export": False}) is True


def test_art20_records_the_legal_basis_and_automated_means_conditions():
    el = load(GDPR).get("norm", "art20_data_export")
    assert el.data["cite"]["url"].endswith("#art_20")
    assert "automated means" in el.data["cite"]["quote"]
    note = el.data["interpretation"]["note"]
    assert "consent" in note and "contract" in note and "automated means" in note
    assert any(d.startswith("Art. 20(1)(a)") for d in el.data["defers_to"])


# -------------------------------------------------- GDPR Art. 32 in transit


def test_art32_transport_plain_http_with_personal_data_fails():
    assert norm(GDPR, "art32_transport_encryption", {"processes_personal_data": True, "tls_enforced": False}) is False


def test_art32_transport_https_enforced_passes():
    assert norm(GDPR, "art32_transport_encryption", {"processes_personal_data": True, "tls_enforced": True}) is True


def test_art32_transport_without_personal_data_passes():
    assert norm(GDPR, "art32_transport_encryption", {"processes_personal_data": False, "tls_enforced": False}) is True


def test_art32_transport_unknown_tls_is_open():
    assert open_facts(norm(GDPR, "art32_transport_encryption", {"processes_personal_data": True})) == ["system.tls_enforced"]


def test_art32_transport_is_an_unsettled_interpretation():
    el = load(GDPR).get("norm", "art32_transport_encryption")
    assert el.data["cite"]["section"] == "Art. 32(1)(a)"
    assert el.data["interpretation"]["by"] == "pack"
    assert str(el.data["interpretation"]["settled"]).startswith("no")


def test_every_norm_has_guidance():
    for pack in (GDPR, UK):
        for (kind, name), el in load(pack).elements.items():
            if kind == "norm":
                assert isinstance(el.data.get("guidance"), str) and len(el.data["guidance"]) > 40, name


# ------------------------------------------------------------------ UK GDPR


def test_uk_replaces_transfer_norm_and_keeps_art17():
    rs = load(UK)
    assert rs.get("norm", "chapter5_transfer_basis").package == "uk-gdpr"
    art17 = rs.get("norm", "art17_erasure_path")
    assert art17.package == "gdpr"
    assert amendment_status(rs, art17, "Art. 17(1)").startswith("Not amended")
    assert amendment_status(rs, None, "Art. 44").startswith("Deleted by")


def test_uk_inherited_art17_still_applies():
    assert norm(UK, "art17_erasure_path", {"processes_personal_data": True, "account_erasure": False}) is False
    assert norm(UK, "art17_erasure_path", {"processes_personal_data": True, "account_erasure": True}) is True


def test_uk_inherits_art20_and_art32_transport_unchanged():
    # legislation.gov.uk Art. 20 and Art. 32(1), (2) read as the EU text: no patch.
    rs = load(UK)
    for name, section in (("art20_data_export", "Art. 20(1)"), ("art32_transport_encryption", "Art. 32(1)(a)")):
        el = rs.get("norm", name)
        assert el.package == "gdpr"
        assert amendment_status(rs, el, section).startswith("Not amended")
    assert norm(UK, "art20_data_export", {"processes_personal_data": True, "account_data_export": False}) is False
    assert norm(UK, "art32_transport_encryption", {"processes_personal_data": True, "tls_enforced": True}) is True


def test_uk_eu_recipient_is_third_country_but_approved():
    # Art. 4(27): an EU recipient is outside the UK; DPA 2018 Sch. 21 para. 5(1)(a)
    # treats transfers to an EEA state as approved under Art. 45A.
    eu = {"personal_data": True, "third_country": True, "approved_by_uk_regulations": True}
    assert norm(UK, "chapter5_transfer_basis", instance=eu) is True


def test_uk_transfer_to_us_without_approval_or_safeguards_fails():
    us = {**US_TRANSFER, "approved_by_uk_regulations": False, "adequacy_or_safeguards": False}
    assert norm(UK, "chapter5_transfer_basis", instance=us) is False


def test_uk_transfer_to_us_with_idta_passes():
    us = {**US_TRANSFER, "approved_by_uk_regulations": False, "adequacy_or_safeguards": True}
    assert norm(UK, "chapter5_transfer_basis", instance=us) is True


def test_uk_transfer_basis_unknown_names_both_facts():
    v = norm(UK, "chapter5_transfer_basis", instance=US_TRANSFER)
    assert open_facts(v) == ["Transfer.adequacy_or_safeguards", "Transfer.approved_by_uk_regulations"]


# --------------------------------------------------------------------- APPI

US_APPI = {"personal_data": True, "appi_recipient_location": "other", "appi_equivalent_measures_system": False}


def test_appi28_us_transfer_without_consent_fails():
    assert norm(APPI, "appi28_foreign_transfer", instance={**US_APPI, "appi_principal_consent": False}) is False


def test_appi28_us_transfer_with_prior_consent_passes():
    assert norm(APPI, "appi28_foreign_transfer", instance={**US_APPI, "appi_principal_consent": True}) is True


def test_appi28_designated_country_or_kijun_tekigo_taisei_needs_no_consent():
    # 規則第15条 / 告示 2項: EEA states and 英国 are not 外国; 規則第16条: a recipient with
    # a 基準適合体制 is not a 第三者 for 第28条.
    for loc in ("eea", "uk"):
        assert norm(APPI, "appi28_foreign_transfer", instance={**US_APPI, "appi_recipient_location": loc}) is True
    assert norm(APPI, "appi28_foreign_transfer", instance={**US_APPI, "appi_equivalent_measures_system": True}) is True


def test_appi28_consent_unknown_stays_open():
    v = norm(APPI, "appi28_foreign_transfer", instance=US_APPI)
    assert open_facts(v) == ["Transfer.appi_principal_consent"]


def test_appi23_md5_fails_and_argon2_passes():
    assert norm(APPI, "appi23_password_hashing", instance={"algorithm": "md5", "salted": True}) is False
    assert norm(APPI, "appi23_password_hashing", instance={"algorithm": "argon2", "salted": True}) is True


# ---------------------------------------------------------------- evidence


def test_evidence_run_gdpr():
    doc = {
        "subject": {"kind": "system", "id": "shop"},
        "sources": [{"id": "static", "kind": "adapter", "describes": "shop@abc123"}],
        "facts": {"processes_personal_data": [{"value": True, "at": "models/user.ts:3"}],
                  "account_erasure": [{"value": False, "at": "routes/account.ts:9"}]},
        "elements": [
            {"type": "PasswordStore", "id": "pw", "at": "auth/hash.ts:12",
             "facts": {"algorithm": [{"value": "md5"}], "salted": [{"value": False}]}},
            {"type": "Transfer", "id": "ga", "at": "web/analytics.ts:40",
             "facts": {"recipient": [{"value": "Google Analytics"}], "personal_data": [{"value": True}],
                       "third_country": [{"value": True}]}},
            {"type": "LogStatement", "id": "log", "at": "auth/login.ts:20",
             "facts": {"logs_credentials": [{"value": False}], "logs_personal_data": [{"value": True}]}},
        ],
    }
    rows = {(r["norm"], r["element"]): r for r in run(load(GDPR), load_evidence(doc))}
    assert rows[("art17_erasure_path", "shop")]["verdict"] == "fail"
    # A system-level verdict cites the facts it read, the requirement before the fact that made it apply.
    assert rows[("art17_erasure_path", "shop")]["at"] == ["routes/account.ts:9", "models/user.ts:3"]
    assert rows[("art32_password_hashing", "pw")]["verdict"] == "fail"
    assert rows[("art32_no_credentials_in_logs", "log")]["verdict"] == "pass"
    transfer = rows[("chapter5_transfer_basis", "ga")]
    assert transfer["verdict"] == "unknown"
    assert transfer["open"] == ["Transfer.adequacy_or_safeguards"]
    # A contract fact from the profile settles nothing about elements, so a given
    # element fact must come from another evidence document.
    contracts = {"sources": [{"id": "dpa", "kind": "contract"}],
                 "elements": [{"type": "Transfer", "id": "ga", "facts": {"adequacy_or_safeguards": [{"value": True}]}}]}
    rows = {(r["norm"], r["element"]): r for r in run(load(GDPR), load_evidence(doc, contracts))}
    assert rows[("chapter5_transfer_basis", "ga")]["verdict"] == "pass"
