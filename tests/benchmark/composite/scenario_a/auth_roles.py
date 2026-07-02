"""场景 A - 模块1：无鉴权写入用户角色。"""

from __future__ import annotations

_user_roles: dict[str, str] = {}


def assign_role(user_id: str, role: str) -> None:
    """从请求直接设置角色，未校验调用方是否为管理员。"""
    _user_roles[user_id] = role


def get_role(user_id: str) -> str:
    return _user_roles.get(user_id, "guest")
