import os

from centinela.guards.governance_guard import policy

CONTRACT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "capability_contract.yaml",
)


def test_load_contract_has_expected_keys():
    contract = policy.load_contract(CONTRACT_PATH)

    assert "acciones_permitidas" in contract
    assert "acciones_prohibidas" in contract
    assert "destinos_prohibidos" in contract


def test_evaluate_denies_force_push_to_main():
    contract = policy.load_contract(CONTRACT_PATH)

    result = policy.evaluate(
        {"tool": "Bash", "command": "git push --force origin main"}, contract
    )

    assert result["decision"] == "deny"
    assert result["reason"]


def test_evaluate_allows_harmless_command():
    contract = policy.load_contract(CONTRACT_PATH)

    result = policy.evaluate({"tool": "Bash", "command": "git status"}, contract)

    assert result["decision"] == "allow"


def test_evaluate_denies_rm_rf():
    contract = policy.load_contract(CONTRACT_PATH)

    result = policy.evaluate(
        {"tool": "Bash", "command": "rm -rf /some/important/path"}, contract
    )

    assert result["decision"] == "deny"


def test_evaluate_denies_push_to_produccion_destination():
    contract = policy.load_contract(CONTRACT_PATH)

    result = policy.evaluate(
        {"tool": "Bash", "command": "git push origin produccion"}, contract
    )

    assert result["decision"] == "deny"
