#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""框架安全知识库单元测试。"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from skynet.knowledge.frameworks import (
    FrameworkDetector,
    FrameworkKnowledgeBase,
    FrameworkKnowledge,
    DangerousPattern,
    get_framework_kb,
)


def ok(msg: str) -> None:
    print(f"[PASS] {msg}")


def fail(msg: str) -> None:
    print(f"[FAIL] {msg}")
    sys.exit(1)


def test_framework_detection_flask():
    """检测 Flask 框架。"""
    kb = FrameworkKnowledgeBase()
    code = """
from flask import Flask, render_template
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')
"""
    detected = kb.detect(code)
    assert "flask" in detected, f"应检测到 flask，实际: {detected}"
    ok("检测到 Flask 框架")


def test_framework_detection_django():
    """检测 Django 框架。"""
    kb = FrameworkKnowledgeBase()
    code = """
from django.http import HttpResponse
from django.db import models

class User(models.Model):
    name = models.CharField(max_length=100)
"""
    detected = kb.detect(code)
    assert "django" in detected, f"应检测到 django，实际: {detected}"
    ok("检测到 Django 框架")


def test_framework_detection_express():
    """检测 Express 框架。"""
    kb = FrameworkKnowledgeBase()
    code = """
const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('Hello World');
});
"""
    detected = kb.detect(code)
    assert "express" in detected, f"应检测到 express，实际: {detected}"
    ok("检测到 Express 框架")


def test_framework_detection_fastapi():
    """检测 FastAPI 框架。"""
    kb = FrameworkKnowledgeBase()
    code = """
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}
"""
    detected = kb.detect(code)
    assert "fastapi" in detected, f"应检测到 fastapi，实际: {detected}"
    ok("检测到 FastAPI 框架")


def test_framework_detection_none():
    """无框架代码返回空列表。"""
    kb = FrameworkKnowledgeBase()
    code = """
def hello():
    print("Hello World")
"""
    detected = kb.detect(code)
    assert len(detected) == 0, f"不应检测到框架，实际: {detected}"
    ok("无框架代码返回空列表")


def test_get_knowledge_flask():
    """获取 Flask 安全知识。"""
    kb = FrameworkKnowledgeBase()
    knowledge = kb.get_knowledge("flask")

    assert knowledge is not None
    assert knowledge.name == "Flask"
    assert len(knowledge.dangerous_patterns) > 0
    assert len(knowledge.security_best_practices) > 0

    # 检查 SSTI 模式
    ssti = next((p for p in knowledge.dangerous_patterns if p.id == "flask_ssti"), None)
    assert ssti is not None, "应有 SSTI 危险模式"
    assert ssti.severity == "critical"
    ok(f"Flask 知识: {len(knowledge.dangerous_patterns)} 个危险模式")


def test_get_knowledge_unknown():
    """未知框架返回 None。"""
    kb = FrameworkKnowledgeBase()
    knowledge = kb.get_knowledge("unknown_framework")
    assert knowledge is None
    ok("未知框架返回 None")


def test_get_prompt_context():
    """获取 prompt 上下文格式正确。"""
    kb = FrameworkKnowledgeBase()
    context = kb.get_prompt_context("flask")

    assert "Flask Security Knowledge" in context
    assert "Dangerous Patterns" in context
    assert "Best Practices" in context
    assert "SSTI" in context or "Template Injection" in context
    ok("Flask prompt 上下文格式正确")


def test_get_prompt_context_unknown():
    """未知框架返回空字符串。"""
    kb = FrameworkKnowledgeBase()
    context = kb.get_prompt_context("unknown")
    assert context == ""
    ok("未知框架 prompt 上下文为空")


def test_knowledge_base_loaded():
    """知识库正确加载。"""
    kb = FrameworkKnowledgeBase()
    assert kb.is_loaded() is True

    ids = kb.get_all_framework_ids()
    assert "flask" in ids
    assert "django" in ids
    assert "express" in ids
    assert "fastapi" in ids
    ok(f"知识库加载: {len(ids)} 个框架")


def test_global_kb():
    """全局知识库单例。"""
    kb1 = get_framework_kb()
    kb2 = get_framework_kb()
    assert kb1 is kb2
    ok("全局知识库单例正确")


def test_dangerous_pattern_structure():
    """DangerousPattern 数据结构正确。"""
    kb = FrameworkKnowledgeBase()
    knowledge = kb.get_knowledge("django")

    assert knowledge is not None
    for pattern in knowledge.dangerous_patterns:
        assert isinstance(pattern, DangerousPattern)
        assert pattern.id != ""
        assert pattern.title != ""
        assert len(pattern.cwe_ids) > 0
        assert pattern.severity in ("critical", "high", "medium", "low")
        assert len(pattern.patterns) > 0
        assert len(pattern.safe_alternatives) > 0
    ok("DangerousPattern 结构正确")


def main():
    print("=" * 60)
    print("框架安全知识库测试")
    print("=" * 60)

    test_framework_detection_flask()
    test_framework_detection_django()
    test_framework_detection_express()
    test_framework_detection_fastapi()
    test_framework_detection_none()
    test_get_knowledge_flask()
    test_get_knowledge_unknown()
    test_get_prompt_context()
    test_get_prompt_context_unknown()
    test_knowledge_base_loaded()
    test_global_kb()
    test_dangerous_pattern_structure()

    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)


if __name__ == "__main__":
    main()
