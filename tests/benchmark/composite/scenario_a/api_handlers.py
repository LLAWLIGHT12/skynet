"""场景 A - 模块2：读取角色执行敏感操作，无会话/权限二次校验。"""

from __future__ import annotations

from auth_roles import get_role

_ADMIN_ACTIONS = {"delete_user", "export_data", "grant_admin"}


def handle_admin_action(requester_id: str, action: str, target_id: str) -> dict:
    """仅检查内存中的 role 字符串，未验证会话或操作授权链。"""
    role = get_role(requester_id)
    if role == "admin" and action in _ADMIN_ACTIONS:
        return {"ok": True, "action": action, "target": target_id}
    return {"ok": False, "error": "forbidden"}


def public_endpoint(user_id: str) -> dict:
    """公开入口可间接影响角色状态（供组合分析关联）。"""
    role = get_role(user_id)
    return {"user_id": user_id, "role": role}
