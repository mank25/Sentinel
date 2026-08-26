"""Minimal runner so each test module also works as ``python -m``.

The suites are plain ``test_*`` functions, so pytest collects them too.
"""

import sys
import traceback


def run_module_tests(namespace: dict) -> int:
    """Run every ``test_*`` callable in ``namespace``; return an exit code."""

    tests = [
        (name, obj)
        for name, obj in sorted(namespace.items())
        if name.startswith("test_") and callable(obj)
    ]

    failures = 0

    for name, test in tests:
        try:
            test()
        except Exception:  # noqa: BLE001 - reported, not propagated
            failures += 1
            print(f"FAIL {name}")
            traceback.print_exc()
        else:
            print(f"PASS {name}")

    print(f"\n{len(tests) - failures}/{len(tests)} passed")

    return 1 if failures else 0


def main(namespace: dict) -> None:
    sys.exit(run_module_tests(namespace))
