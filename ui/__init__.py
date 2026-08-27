"""Sentinel's operator console: a browser front end for the TrueForge agent.

The console adds no security logic. It drives :class:`trueforge.agent.
SentinelAgent` exactly as the CLI does and renders what the harness reports:
the tools TrueForge actually called, and the containment call it paused on.

The approval gate is the reason this exists. A trace scrolling past in a
terminal does not show an operator what the agent wants to do to a production
account; a button that says "Approve" next to the account name does.
"""
