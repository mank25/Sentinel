"""Demo orchestration for Sentinel.

This package contains no security logic. It exists so a judge can run one
command instead of five: readiness checks (:mod:`sentinel.preflight`), a
repeatable demo state (:mod:`sentinel.demo`), and the narration that turns an
investigation into something watchable.

Everything it drives lives elsewhere and is unchanged by its presence --
evidence stays read-only, scoring stays in ``investigator/risk.py``, and the
approval gate stays in the harness.
"""
