"""Minimal sink sample for taint flow testing."""

import os
import sqlite3


def get_user_input(request_data: dict) -> str:
    return request_data.get("name", "")


def build_query(name: str) -> str:
    return f"SELECT * FROM users WHERE name = '{name}'"


def run_query(query: str) -> list:
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(query)
    return cur.fetchall()


def handle_request(request_data: dict) -> list:
    name = get_user_input(request_data)
    query = build_query(name)
    return run_query(query)
