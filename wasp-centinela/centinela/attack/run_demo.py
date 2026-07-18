"""Console demo for the WASP attack simulator.

Run from the project root (target server must already be running on
127.0.0.1:8899, see tests/fixtures/vuln_sample_repo/server.py):

    .venv\\Scripts\\python.exe -m centinela.attack.run_demo

Prints each attack step to the console the moment it finishes -- not
batched at the end -- by passing an on_step callback into
centinela.attack.simulator.run_attack. This module knows nothing about how
run_attack works internally; it only reacts to the callback, so a Telegram
bot or a dashboard could plug in the same way without touching simulator.py.
"""

from centinela.attack.simulator import run_attack

VECTOR_LABELS = {
    "fuerza_bruta": "Fuerza bruta",
    "sql_injection": "Inyeccion SQL",
    "command_injection": "Inyeccion de comando",
}

TOTAL_STEPS = 3


def main() -> None:
    print("WASP - simulador de ataque en vivo")
    print("=" * 40)

    step_number = 0

    def on_step(step_result: dict) -> None:
        nonlocal step_number
        step_number += 1
        label = VECTOR_LABELS.get(step_result["vector"], step_result["vector"])
        status = "EXITO" if step_result["success"] else "FALLO"
        print(
            f"[{step_number}/{TOTAL_STEPS}] {label}... {status} "
            f"({step_result['evidence']})"
        )

    run_attack(on_step=on_step)

    print("=" * 40)
    print("Ataque finalizado.")


if __name__ == "__main__":
    main()
