#!/usr/bin/env python3
"""
Alice & Bob Secure Communication Demo
======================================
End-to-end demonstration of the secure channel protocol.
Run:  python examples/alice_bob_demo.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secure_channel import alice_bob_demo

if __name__ == "__main__":
    alice_bob_demo()
