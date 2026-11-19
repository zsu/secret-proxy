"""Script file for ``mitmdump -s`` (mitmproxy loads addons from a path).

``secretproxy run`` passes this file automatically; you only need it when
starting mitmdump by hand.
"""
from secretproxy.addon import addons  # noqa: F401
