"""Fuzzing Harness 生成器 — 根据漏洞类型生成验证代码模板。

支持多语言（Python/PHP/JS/Go/Java/Bash），
为每种漏洞类型提供预定义的验证模板。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class HarnessTemplate:
    """Harness 模板。"""
    vuln_type: str
    language: str
    template: str
    description: str


# 漏洞类型 -> 多语言 Harness 模板
_HARNESS_TEMPLATES: Dict[str, Dict[str, str]] = {
    "sql_injection": {
        "python": '''"""SQL Injection PoC Harness"""
import sqlite3
import sys

def test_sql_injection(user_input):
    """测试 SQL 注入漏洞。"""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")

    # 漏洞代码模式
    try:
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        cursor.execute(query)
        results = cursor.fetchall()
        print(f"Query: {{query}}")
        print(f"Results: {{results}}")
        # 如果返回多行或包含密码，说明注入成功
        if len(results) > 1 or "secret" in str(results):
            print("[VULNERABLE] SQL injection successful")
            return True
    except Exception as e:
        print(f"[ERROR] {{e}}")
    return False

if __name__ == "__main__":
    payloads = ["' OR '1'='1", "' UNION SELECT 1,2,3 --", "admin'--"]
    for payload in payloads:
        print(f"\\nTesting payload: {{payload}}")
        test_sql_injection(payload)
''',
        "php": '''<?php
// SQL 注入 PoC - PHP + MySQL (模拟)
$payloads = ["' OR '1'='1", "' UNION SELECT 1,2,3 --", "admin'--"];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    $query = "SELECT * FROM users WHERE name = '$payload'";
    echo "Query: $query\\n";
    // 检测注入特征
    if (strpos($payload, "'") !== false || stripos($payload, "union") !== false) {
        echo "[VULNERABLE] SQL injection detected\\n";
    }
    // 安全版本
    $safe_query = "SELECT * FROM users WHERE name = '" . addslashes($payload) . "'";
    echo "Safe query: $safe_query\\n";
}
?>
''',
        "javascript": '''// SQL 注入 PoC - Node.js + SQLite
const payloads = ["' OR '1'='1", "' UNION SELECT 1,2,3 --", "admin'--"];
for (const payload of payloads) {
    const query = `SELECT * FROM users WHERE name = '${payload}'`;
    console.log("Query:", query);
    if (payload.includes("'") || payload.toLowerCase().includes("union")) {
        console.log("[VULNERABLE] SQL injection detected");
    }
}
''',
        "java": '''import java.sql.*;

public class SQLiTest {
    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        stmt.execute("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)");
        stmt.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')");
        
        String[] payloads = {"' OR '1'='1", "' UNION SELECT 1,2,3 --"};
        for (String payload : payloads) {
            String query = "SELECT * FROM users WHERE name = '" + payload + "'";
            System.out.println("Query: " + query);
            try {
                ResultSet rs = stmt.executeQuery(query);
                while (rs.next()) {
                    System.out.println("Result: " + rs.getString("name"));
                }
                System.out.println("[VULNERABLE] SQL injection executed");
            } catch (SQLException e) {
                System.out.println("[ERROR] " + e.getMessage());
            }
        }
    }
}
''',
        "go": '''package main

import (
    "database/sql"
    "fmt"
    _ "github.com/mattn/go-sqlite3"
    "strings"
)

func main() {
    db, _ := sql.Open("sqlite3", ":memory:")
    defer db.Close()
    db.Exec("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)")
    db.Exec("INSERT INTO users VALUES (1, 'admin', 'secret123')")
    
    payloads := []string{"' OR '1'='1", "' UNION SELECT 1,2,3 --"}
    for _, payload := range payloads {
        query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", payload)
        fmt.Println("Query:", query)
        if strings.Contains(payload, "'") || strings.Contains(strings.ToLower(payload), "union") {
            fmt.Println("[VULNERABLE] SQL injection detected")
        }
    }
}
''',
    },
    "command_injection": {
        "python": '''"""Command Injection PoC Harness"""
import subprocess
import sys

def test_command_injection(user_input):
    """测试命令注入漏洞。"""
    # 漏洞代码模式
    cmd = f"echo {user_input}"
    print(f"Command: {cmd}")

    try:
        # 使用 shell=True 模拟漏洞
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        print(f"Output: {result.stdout}")
        # 检查是否执行了注入的命令
        if "INJECTED" in result.stdout or result.returncode != 0:
            print("[VULNERABLE] Command injection detected")
            return True
    except subprocess.TimeoutExpired:
        print("[TIMEOUT] Command timed out")
    except Exception as e:
        print(f"[ERROR] {e}")
    return False

if __name__ == "__main__":
    payloads = [
        "; echo INJECTED",
        "| echo INJECTED",
        "$(echo INJECTED)",
        "`echo INJECTED`",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_command_injection(payload)
''',
        "php": '''<?php
// 命令注入 PoC - PHP
$payloads = ["; echo INJECTED", "| echo INJECTED", "$(echo INJECTED)"];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    // 模拟不安全命令执行
    $cmd = "echo " . $payload;
    echo "Command: $cmd\\n";
    // 检测注入特征
    if (strpos($payload, ";") !== false || strpos($payload, "|") !== false) {
        echo "[VULNERABLE] Command injection detected\\n";
    }
}
?>
''',
        "javascript": '''// 命令注入 PoC - Node.js
const { execSync } = require('child_process');
const payloads = ['; echo INJECTED', '| echo INJECTED', '$(echo INJECTED)'];
for (const payload of payloads) {
    const cmd = `echo ${payload}`;
    console.log(`Command: ${cmd}`);
    if (payload.includes(';') || payload.includes('|') || payload.includes('$(')) {
        console.log('[VULNERABLE] Command injection detected');
    }
}
''',
        "go": '''package main

import (
    "fmt"
    "os/exec"
    "strings"
)

func main() {
    payloads := []string{"; echo INJECTED", "| echo INJECTED", "$(echo INJECTED)"}
    for _, payload := range payloads {
        cmd := fmt.Sprintf("echo %s", payload)
        fmt.Printf("Command: %s\\n", cmd)
        if strings.Contains(payload, ";") || strings.Contains(payload, "$(") {
            fmt.Println("[VULNERABLE] Command injection detected")
        }
    }
}
''',
        "ruby": '''# 命令注入 PoC - Ruby
payloads = ["; echo INJECTED", "| echo INJECTED", "$(echo INJECTED)"]
payloads.each do |payload|
  cmd = "echo #{payload}"
  puts "Command: #{cmd}"
  if payload.include?(";") || payload.include?("$(")
    puts "[VULNERABLE] Command injection detected"
  end
end
''',
        "shell": '''#!/bin/bash
# 命令注入 PoC - Shell
payloads=("; echo INJECTED" "| echo INJECTED" "$(echo INJECTED)")
for payload in "${payloads[@]}"; do
    cmd="echo $payload"
    echo "Command: $cmd"
    if [[ "$payload" == *";"* ]] || [[ "$payload" == *"$("* ]]; then
        echo "[VULNERABLE] Command injection detected"
    fi
done
''',
    },
    "xss": {
        "python": '''"""XSS PoC Harness"""
import html

def test_xss(user_input):
    """测试 XSS 漏洞。"""
    # 模拟漏洞场景：直接嵌入 HTML
    template = f"<div>{user_input}</div>"
    print(f"Generated HTML: {template}")

    # 检查是否包含脚本标签
    dangerous_patterns = ["<script", "onerror=", "onload=", "javascript:"]
    for pattern in dangerous_patterns:
        if pattern.lower() in template.lower():
            print(f"[VULNERABLE] XSS payload detected: {pattern}")
            return True

    # 安全版本
    safe_output = html.escape(user_input)
    safe_template = f"<div>{safe_output}</div>"
    print(f"Safe HTML: {safe_template}")
    return False

if __name__ == "__main__":
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>document.location="http://evil.com"</script>',
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_xss(payload)
''',
        "php": '''<?php
// XSS PoC - PHP
$payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>document.location="http://evil.com"</script>',
];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    $html = "<div>$payload</div>";
    echo "Generated HTML: $html\\n";
    // 检测 XSS 特征
    if (preg_match('/<script|onerror=|onload=|javascript:/i', $payload)) {
        echo "[VULNERABLE] XSS payload detected\\n";
    }
    // 安全版本
    $safe = htmlspecialchars($payload, ENT_QUOTES, 'UTF-8');
    echo "Safe HTML: <div>$safe</div>\\n";
}
?>
''',
        "javascript": '''// XSS PoC - Node.js
const payloads = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    '"><script>document.location="http://evil.com"</script>',
];
for (const payload of payloads) {
    const html = `<div>${payload}</div>`;
    console.log("Generated HTML:", html);
    if (/<script|onerror=|onload=|javascript:/i.test(payload)) {
        console.log("[VULNERABLE] XSS payload detected");
    }
}
''',
    },
    "path_traversal": {
        "python": '''"""Path Traversal PoC Harness"""
import os

def test_path_traversal(user_input, base_dir="/tmp"):
    """测试路径遍历漏洞。"""
    # 漏洞代码模式
    filepath = os.path.join(base_dir, user_input)
    print(f"Requested path: {filepath}")

    # 检查是否遍历了基础目录
    real_path = os.path.realpath(filepath)
    real_base = os.path.realpath(base_dir)
    print(f"Real path: {real_path}")
    print(f"Base dir: {real_base}")

    if not real_path.startswith(real_base):
        print(f"[VULNERABLE] Path traversal detected!")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        "../../etc/passwd",
        "..\\\\..\\\\windows\\\\system32",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_path_traversal(payload)
''',
        "php": '''<?php
// 路径遍历 PoC - PHP
$base_dir = "/tmp";
$payloads = ["../../etc/passwd", "..\\..\\windows\\system32", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    $filepath = $base_dir . "/" . $payload;
    echo "Requested path: $filepath\\n";
    $real_path = realpath($filepath);
    $real_base = realpath($base_dir);
    echo "Real path: $real_path\\n";
    if ($real_path !== false && strpos($real_path, $real_base) !== 0) {
        echo "[VULNERABLE] Path traversal detected!\\n";
    }
}
?>
''',
        "javascript": '''// 路径遍历 PoC - Node.js
const path = require('path');
const baseDir = '/tmp';
const payloads = ['../../etc/passwd', '..\\\\..\\\\windows\\\\system32', '%2e%2e%2f%2e%2e%2fetc%2fpasswd'];
for (const payload of payloads) {
    console.log(`Testing: ${payload}`);
    const filepath = path.join(baseDir, payload);
    console.log(`Requested path: ${filepath}`);
    const realPath = path.resolve(filepath);
    const realBase = path.resolve(baseDir);
    console.log(`Real path: ${realPath}`);
    if (!realPath.startsWith(realBase)) {
        console.log('[VULNERABLE] Path traversal detected!');
    }
}
''',
        "java": '''import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathTraversalTest {
    public static void main(String[] args) throws Exception {
        String baseDir = "/tmp";
        String[] payloads = {"../../etc/passwd", "..\\..\\windows\\system32"};
        for (String payload : payloads) {
            System.out.println("Testing: " + payload);
            Path filePath = Paths.get(baseDir, payload).normalize();
            Path basePath = Paths.get(baseDir).normalize();
            System.out.println("Resolved: " + filePath);
            if (!filePath.startsWith(basePath)) {
                System.out.println("[VULNERABLE] Path traversal detected!");
            }
        }
    }
}
''',
        "go": '''package main

import (
    "fmt"
    "path/filepath"
    "strings"
)

func main() {
    baseDir := "/tmp"
    payloads := []string{"../../etc/passwd", "..\\..\\windows\\system32"}
    for _, payload := range payloads {
        fmt.Printf("Testing: %s\\n", payload)
        fullPath := filepath.Join(baseDir, payload)
        cleanPath := filepath.Clean(fullPath)
        fmt.Printf("Resolved: %s\\n", cleanPath)
        if !strings.HasPrefix(cleanPath, filepath.Clean(baseDir)) {
            fmt.Println("[VULNERABLE] Path traversal detected!")
        }
    }
}
''',
    },
    "ssrf": {
        "python": '''"""SSRF PoC Harness"""
import urllib.parse

def test_ssrf(user_url):
    """测试 SSRF 漏洞。"""
    parsed = urllib.parse.urlparse(user_url)
    print(f"URL: {user_url}")
    print(f"Scheme: {parsed.scheme}")
    print(f"Host: {parsed.hostname}")

    # 检查危险目标
    dangerous_hosts = ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0", "metadata"]
    dangerous_schemes = ["file", "gopher", "dict"]

    if parsed.hostname in dangerous_hosts:
        print(f"[VULNERABLE] SSRF to internal service: {parsed.hostname}")
        return True
    if parsed.scheme in dangerous_schemes:
        print(f"[VULNERABLE] Dangerous scheme: {parsed.scheme}")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://localhost:6379/",
        "gopher://evil.com/",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_ssrf(payload)
''',
        "php": '''<?php
// SSRF PoC - PHP
$payloads = [
    "http://169.254.169.254/latest/meta-data/",
    "file:///etc/passwd",
    "http://localhost:6379/",
];
$dangerous_hosts = ["169.254.169.254", "localhost", "127.0.0.1", "0.0.0.0"];
$dangerous_schemes = ["file", "gopher", "dict"];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    $parsed = parse_url($payload);
    if (in_array($parsed["host"], $dangerous_hosts) || in_array($parsed["scheme"], $dangerous_schemes)) {
        echo "[VULNERABLE] SSRF detected\\n";
    }
}
?>
''',
        "javascript": '''// SSRF PoC - Node.js
const { URL } = require('url');
const dangerousHosts = ['169.254.169.254', 'localhost', '127.0.0.1', '0.0.0.0'];
const dangerousSchemes = ['file:', 'gopher:', 'dict:'];
const payloads = [
    'http://169.254.169.254/latest/meta-data/',
    'file:///etc/passwd',
    'http://localhost:6379/',
];
for (const payload of payloads) {
    const url = new URL(payload);
    console.log("Testing:", payload);
    if (dangerousHosts.includes(url.hostname) || dangerousSchemes.includes(url.protocol)) {
        console.log("[VULNERABLE] SSRF detected");
    }
}
''',
        "java": '''import java.net.URL;

public class SSRFTest {
    public static void main(String[] args) throws Exception {
        String[] payloads = {
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://localhost:6379/"
        };
        String[] dangerousHosts = {"169.254.169.254", "localhost", "127.0.0.1"};
        for (String payload : payloads) {
            URL url = new URL(payload);
            System.out.println("Testing: " + payload);
            for (String host : dangerousHosts) {
                if (url.getHost().equals(host)) {
                    System.out.println("[VULNERABLE] SSRF detected: " + url.getHost());
                }
            }
        }
    }
}
''',
        "go": '''package main

import (
    "fmt"
    "net/url"
)

func main() {
    dangerousHosts := map[string]bool{"169.254.169.254": true, "localhost": true, "127.0.0.1": true}
    dangerousSchemes := map[string]bool{"file": true, "gopher": true, "dict": true}
    payloads := []string{
        "http://169.254.169.254/latest/meta-data/",
        "file:///etc/passwd",
        "http://localhost:6379/",
    }
    for _, payload := range payloads {
        u, _ := url.Parse(payload)
        fmt.Println("Testing:", payload)
        if dangerousHosts[u.Hostname()] || dangerousSchemes[u.Scheme] {
            fmt.Println("[VULNERABLE] SSRF detected")
        }
    }
}
''',
    },
    "nosql_injection": {
        "python": '''"""NoSQL Injection PoC Harness"""
def test_nosql_injection(user_input):
    """测试 NoSQL 注入漏洞 (MongoDB 风格)。"""
    # 模拟 MongoDB 查询
    query = {"username": user_input, "password": {"$gt": ""}}
    print(f"Generated query: {query}")
    # 检测注入特征
    if isinstance(user_input, dict) or "$" in str(user_input):
        print("[VULNERABLE] NoSQL injection detected")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        {"$gt": ""},
        {"$ne": None},
        {"$regex": ".*"},
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_nosql_injection(payload)
''',
        "javascript": '''// NoSQL Injection PoC Harness (Node.js + MongoDB style)
const payloads = [
    { $gt: "" },
    { $ne: null },
    { $regex: ".*" },
];
for (const payload of payloads) {
    const query = { username: payload, password: { $gt: "" } };
    console.log("Query:", JSON.stringify(query));
    if (typeof payload === "object" && JSON.stringify(payload).includes("$")) {
        console.log("[VULNERABLE] NoSQL injection detected");
    }
}
''',
    },
    "xxe": {
        "python": '''"""XXE PoC Harness"""
import xml.etree.ElementTree as ET

def test_xxe(xml_input):
    """测试 XXE 漏洞。"""
    try:
        # 不安全解析
        root = ET.fromstring(xml_input)
        for child in root:
            print(f"Tag: {child.tag}, Text: {child.text}")
        # 检查是否泄露了系统信息
        if "root:" in str(ET.tostring(root)):
            print("[VULNERABLE] XXE: system file content leaked")
            return True
    except ET.ParseError as e:
        print(f"[ERROR] {e}")
    return False

if __name__ == "__main__":
    payloads = [
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>""",
        """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><data>&xxe;</data>""",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload[:80]}...")
        test_xxe(payload)
''',
        "java": '''import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import java.io.*;

public class XXETest {
    public static void main(String[] args) throws Exception {
        String xml = "<?xml version=\\"1.0\\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \\"file:///etc/passwd\\">]><data>&xxe;</data>";
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // 不安全: 未禁用外部实体
        DocumentBuilder builder = factory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(xml));
        builder.parse(is);
        System.out.println("[VULNERABLE] XXE parsed without protection");
    }
}
''',
    },
    "deserialization": {
        "python": '''"""Deserialization PoC Harness"""
import pickle
import base64

def test_deserialization(data_b64):
    """测试反序列化漏洞。"""
    try:
        data = base64.b64decode(data_b64)
        obj = pickle.loads(data)
        print(f"Deserialized: {obj}")
        print("[VULNERABLE] Unsafe deserialization executed")
        return True
    except Exception as e:
        print(f"[ERROR] {e}")
    return False

if __name__ == "__main__":
    # 安全测试: 构造无害 payload
    safe_payload = pickle.dumps({"test": "data"})
    safe_b64 = base64.b64encode(safe_payload).decode()
    print(f"Testing with safe payload: {safe_b64[:50]}...")
    test_deserialization(safe_b64)
''',
        "java": '''import java.io.*;
import java.util.Base64;

public class DeserTest {
    public static void main(String[] args) throws Exception {
        // 测试反序列化
        String b64 = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmALAAJGABxsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHB3D0AAAAxAAAAAAHg=";
        byte[] data = Base64.getDecoder().decode(b64);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
        System.out.println("Deserialized: " + obj.getClass().getName());
        System.out.println("[VULNERABLE] Unsafe deserialization executed");
    }
}
''',
    },
    "ssti": {
        "python": '''"""SSTI PoC Harness"""
from jinja2 import Template

def test_ssti(user_input):
    """测试模板注入漏洞。"""
    # 不安全: 直接将用户输入作为模板
    try:
        template = Template(user_input)
        result = template.render()
        print(f"Rendered: {result}")
        # 检查是否执行了代码
        if any(x in str(result) for x in ["49", "class", "subclasses", "os."]):
            print("[VULNERABLE] SSTI code execution detected")
            return True
    except Exception as e:
        print(f"[ERROR] {e}")
    return False

if __name__ == "__main__":
    payloads = [
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_ssti(payload)
''',
        "php": '''<?php
// SSTI PoC - Twig 模板注入
$payloads = [
    "{{7*7}}",
    "{{_self.env.display(\"/etc/passwd\")}}",
    "{{app.request.server.all}}",
];
foreach ($payloads as $payload) {
    echo "Testing: $payload\\n";
    // 模拟不安全的模板渲染
    if (preg_match(\'/\\{\\{.*\\}\\}/\', $payload)) {
        echo "[VULNERABLE] Template injection detected\\n";
    }
}
?>
''',
    },
    "ldap_injection": {
        "python": '''"""LDAP Injection PoC Harness"""
def test_ldap_injection(user_input):
    """测试 LDAP 注入漏洞。"""
    # 模拟 LDAP 查询构造
    query = f"(&(uid={user_input})(userPassword=*))"
    print(f"Generated LDAP query: {query}")
    # 检测注入特征
    dangerous_chars = ["*", "(", ")", "\\", "|", "&"]
    if any(c in user_input for c in dangerous_chars):
        print("[VULNERABLE] LDAP injection: dangerous characters in input")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        "*)(uid=*))(|(uid=*",
        "admin)(&)",
        "*)(objectClass=*",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_ldap_injection(payload)
''',
    },
    "xpath_injection": {
        "python": '''"""XPath Injection PoC Harness"""
def test_xpath_injection(user_input):
    """测试 XPath 注入漏洞。"""
    # 模拟 XPath 查询构造
    query = f"//user[name='{user_input}']"
    print(f"Generated XPath query: {query}")
    # 检测注入特征
    dangerous = ["'", '"', "or", "and", "//", "/*"]
    if any(d in user_input.lower() for d in dangerous):
        print("[VULNERABLE] XPath injection detected")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        "' or '1'='1",
        "' or 1=1 or '",
        "admin'//",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_xpath_injection(payload)
''',
    },
    "open_redirect": {
        "python": '''"""Open Redirect PoC Harness"""
import urllib.parse

def test_open_redirect(user_url):
    """测试开放重定向漏洞。"""
    parsed = urllib.parse.urlparse(user_url)
    print(f"Redirect target: {user_url}")
    # 检查是否指向外部域名
    dangerous_hosts = ["evil.com", "attacker.com", "phishing.site"]
    if parsed.hostname in dangerous_hosts or parsed.scheme in ["javascript", "data"]:
        print(f"[VULNERABLE] Open redirect to: {parsed.hostname or parsed.scheme}")
        return True
    return False

if __name__ == "__main__":
    payloads = [
        "http://evil.com/phishing",
        "//evil.com",
        "javascript:alert(document.cookie)",
        "/redirect?url=http://evil.com",
    ]
    for payload in payloads:
        print(f"\\nTesting payload: {payload}")
        test_open_redirect(payload)
''',
    },
}


class HarnessGenerator:
    """Fuzzing Harness 生成器。

    用法::

        gen = HarnessGenerator()
        harness = gen.generate("sql_injection", language="python")
        # harness 是可执行的 Python 代码字符串
    """

    def __init__(self):
        self._templates = _HARNESS_TEMPLATES

    def generate(
        self,
        vuln_type: str,
        language: str = "python",
        custom_payloads: Optional[List[str]] = None,
    ) -> Optional[str]:
        """生成 Fuzzing Harness 代码。

        Args:
            vuln_type: 漏洞类型（如 "sql_injection"）。
            language: 目标语言。
            custom_payloads: 自定义攻击载荷（可选）。

        Returns:
            可执行的代码字符串，如果找不到模板则返回 None。
        """
        templates = self._templates.get(vuln_type)
        if templates is None:
            logger.warning("No harness template for vuln type: %s", vuln_type)
            return None

        template = templates.get(language)
        if template is None:
            # 尝试 fallback 到 Python
            template = templates.get("python")
            if template is None:
                logger.warning("No harness template for %s/%s", vuln_type, language)
                return None

        # 如果有自定义载荷，注入到代码中
        if custom_payloads:
            template = self._inject_payloads(template, custom_payloads, language)

        return template

    def _inject_payloads(
        self,
        template: str,
        payloads: List[str],
        language: str,
    ) -> str:
        """将自定义载荷注入模板。"""
        if language == "python":
            payload_str = str(payloads)
            # 替换默认的 payloads 列表
            if "payloads = [" in template:
                lines = template.split("\n")
                new_lines = []
                in_payloads = False
                for line in lines:
                    if "payloads = [" in line:
                        new_lines.append(f"    payloads = {payload_str}")
                        in_payloads = True
                    elif in_payloads and "]" in line:
                        in_payloads = False
                    elif not in_payloads:
                        new_lines.append(line)
                return "\n".join(new_lines)

        return template

    def get_supported_types(self) -> List[str]:
        """获取支持的漏洞类型列表。"""
        return list(self._templates.keys())

    def get_supported_languages(self, vuln_type: str) -> List[str]:
        """获取指定漏洞类型支持的语言列表。"""
        templates = self._templates.get(vuln_type, {})
        return list(templates.keys())

    def has_template(self, vuln_type: str, language: str = "python") -> bool:
        """检查是否有指定漏洞/语言的模板。"""
        templates = self._templates.get(vuln_type)
        if templates is None:
            return False
        return language in templates or "python" in templates
