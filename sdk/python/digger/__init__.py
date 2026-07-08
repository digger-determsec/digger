# Digger Python SDK — wraps the public REST API.
"""
Usage:
    from digger import DiggerClient

    client = DiggerClient("http://localhost:3000")
    result = client.scan("pragma solidity ^0.8.0; contract Foo {}", "solidity")
    print(result["findings"])
"""

from .client import DiggerClient
