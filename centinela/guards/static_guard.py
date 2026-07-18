"""Static analysis guard — orchestrates Semgrep + Gitleaks scanning.

Runs both CLI-backed scanners, merges their normalized findings, reduces
noise (dedupe + priority ordering) via ``noise_guard``, and records every
surviving finding in the tamper-evident ledger via ``hash_chain``.
"""

from centinela.guards import gitleaks_wrapper, noise_guard, semgrep_client
from centinela.ledger import hash_chain


def scan(target_path: str) -> list:
    """Run the full static guard pipeline against ``target_path``.

    Returns the deduplicated, priority-sorted list of findings. Each
    finding in the returned list is also appended to the ledger as a
    ``"finding"`` entry.
    """
    semgrep_findings = semgrep_client.run_semgrep(target_path)
    gitleaks_findings = gitleaks_wrapper.run_gitleaks(target_path)

    combined = semgrep_findings + gitleaks_findings
    deduplicated = noise_guard.deduplicate(combined)
    prioritized = noise_guard.prioritize(deduplicated)

    for finding in prioritized:
        hash_chain.append("finding", finding)

    return prioritized
