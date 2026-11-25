import json
from hashlib import sha256


class Denied(ValueError):
    """An input or runtime transition failed admission."""


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def digest(raw):
    return sha256(raw).hexdigest()


def wire(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise Denied("invalid JSON value") from None


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def decode(raw, limit, label):
    require(type(raw) is bytes and len(raw) <= limit, f"{label} exceeds wire limit or is not bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
    except (ValueError, RecursionError):
        raise Denied(f"invalid {label} JSON") from None
    wire(value)  # Reject non-finite numbers and invalid Unicode, including escapes.
    return value
