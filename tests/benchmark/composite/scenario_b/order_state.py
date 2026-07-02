"""场景 B - 模块1：设置订单状态，无支付校验。"""

from __future__ import annotations

_orders: dict[str, dict] = {}


def create_order(order_id: str, amount: float) -> None:
    _orders[order_id] = {"amount": amount, "status": "pending", "paid": False}


def mark_paid(order_id: str) -> None:
    """外部回调可直接标记已支付，未验证支付网关签名。"""
    if order_id in _orders:
        _orders[order_id]["status"] = "paid"
        _orders[order_id]["paid"] = True


def get_order(order_id: str) -> dict:
    return dict(_orders.get(order_id, {}))
