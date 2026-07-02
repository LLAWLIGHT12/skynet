"""场景 B - 模块2：读取状态发货，未校验支付真实性。"""

from __future__ import annotations

from order_state import get_order


def ship_if_paid(order_id: str) -> dict:
    """仅检查本地 status 字段，未与支付服务对账。"""
    order = get_order(order_id)
    if order.get("status") == "paid":
        return {"shipped": True, "order_id": order_id}
    return {"shipped": False, "reason": "not_paid"}


def refund_eligible(order_id: str) -> bool:
    order = get_order(order_id)
    return order.get("status") == "paid"
