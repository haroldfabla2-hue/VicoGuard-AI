"""Governance policy engine.

Decides whether a proposed action (e.g. a shell command an AI agent wants
to run) is permitted under a capability contract described in YAML.
"""

import yaml

DEFAULT_CONTRACT_PATH = "capability_contract.yaml"

_DEFAULT_ALLOW_REASON = "Acción dentro del contrato."


def load_contract(path: str = DEFAULT_CONTRACT_PATH) -> dict:
    """Load and parse the capability contract YAML file."""
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def evaluate(action: dict, contract: dict) -> dict:
    """Evaluate a proposed action against the capability contract.

    ``action`` is expected to look like
    ``{"tool": "Bash", "command": "git push --force origin main"}``.

    Denies the action if its command contains (case-insensitive substring)
    any pattern listed in ``contract["acciones_prohibidas"]``, or if it
    combines a forbidden destination from ``contract["destinos_prohibidos"]``
    with a git push (i.e. both "push" and the destination appear in the
    same command). Otherwise the action is allowed.
    """
    command = action.get("command", "") or ""
    command_lower = command.lower()

    acciones_prohibidas = contract.get("acciones_prohibidas") or []
    for pattern in acciones_prohibidas:
        if pattern.lower() in command_lower:
            return {
                "decision": "deny",
                "reason": (
                    f"Este comando está bloqueado porque contiene la acción "
                    f"prohibida \"{pattern}\", una operación peligrosa que "
                    f"puede borrar o sobrescribir trabajo de forma "
                    f"irreversible. El contrato de este agente no permite "
                    f"ejecutarla."
                ),
            }

    destinos_prohibidos = contract.get("destinos_prohibidos") or []
    if "push" in command_lower:
        for destino in destinos_prohibidos:
            if destino.lower() in command_lower:
                return {
                    "decision": "deny",
                    "reason": (
                        f"Este comando está bloqueado porque intenta hacer "
                        f"push hacia \"{destino}\", un destino protegido. "
                        f"Subir cambios directamente ahí podría romper un "
                        f"entorno importante sin revisión previa."
                    ),
                }

    return {"decision": "allow", "reason": _DEFAULT_ALLOW_REASON}
