"""Provenance for the gateway (spec section 3): task binding, taint registry, handles,
deterministic quarantined extractors and hidden-text (injection) detection.

Raw untrusted content never reaches the planner: it is stored behind ``$DOC_n`` handles and the
planner only ever sees ``{"handle", "summary"}``. Values pulled out of a document by
``extract_field`` live behind ``$VAR_n`` handles whose label is *derived* from the document's.
"""

import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

from trishul.contracts.calls import ToolCategory
from trishul.contracts.labels import Label, Level, SourceRef
from trishul.domains.pii import label_pii
from trishul.provenance.handles import HandleStore, OpaqueHandle
from trishul.provenance.labeled import Labeled, derive
from trishul.provenance.lattice import join_all

HANDLE_RE = re.compile(r"^\$(?:DOC|VAR)_[1-9][0-9]*$")
MIN_SUBSTRING = 6

# Result trust table (spec section 3). Keys are (server namespace, tool).
TRUSTED_SYSTEM_RESULTS = frozenset(
    {
        ("upi", "list_payees"),
        ("upi", "get_balance"),
        ("upi", "add_payee"),
        ("upi", "pay_upi"),
        ("mail", "send_email"),
    }
)


@dataclass(frozen=True)
class Task:
    """Trusted-channel task binding: purpose and category come only from here."""

    task_id: str
    principal: str
    purpose: str
    category: ToolCategory
    text: str
    params: Mapping[str, object] = field(default_factory=dict)


def system_label(source_id: str, *, kind: str = "system") -> Label:
    return Label.make(
        Level.TRUSTED_SYSTEM,
        sources=[SourceRef(kind=kind, id=source_id)],  # type: ignore[arg-type]
    )


def model_untrusted(task_id: str) -> Label:
    """Planner literals of unknown origin are untrusted (fail-safe)."""
    return Label.make(Level.UNTRUSTED, sources=[SourceRef(kind="model", id=task_id)])


_CONSTANT = system_label("constant")
_AMOUNT_RE = re.compile(r"(?:₹|rs\.?\s*|inr\s*)?(\d[\d,]*)(?:\.(\d{1,2}))?", re.IGNORECASE)


def _norm(value: str) -> str:
    return value.strip().lower()


def _amount_tokens(text: str) -> set[int]:
    """Rupee amounts in free text, registered both as written and as paise."""
    out: set[int] = set()
    for m in _AMOUNT_RE.finditer(text):
        whole = m.group(1).replace(",", "")
        if not whole:
            continue
        try:
            value = Decimal(f"{whole}.{m.group(2) or '0'}")
        except InvalidOperation:  # pragma: no cover - regex guarantees digits
            continue
        out.add(int(value))
        out.add(int(value * 100))
    return out


def _walk_scalars(value: object) -> Iterable[str | int]:
    if isinstance(value, bool) or value is None:
        return
    if isinstance(value, str | int):
        yield value
    elif isinstance(value, Mapping):
        for v in value.values():
            yield from _walk_scalars(v)
    elif isinstance(value, list | tuple):
        for v in value:
            yield from _walk_scalars(v)


class TaintRegistry:
    """Per-session map from observed values to labels (spec section 3)."""

    def __init__(self) -> None:
        self._task: dict[str, dict[str | int, Label]] = {}
        self._exact: dict[str | int, Label] = {}
        self._substr: list[tuple[str, Label]] = []

    # --- registration --------------------------------------------------------------------
    def register_task(self, task: Task) -> None:
        label = Label.make(Level.TRUSTED_USER, sources=[SourceRef(kind="user", id=task.task_id)])
        tokens: dict[str | int, Label] = {}

        def add(value: str | int) -> None:
            key: str | int = _norm(value) if isinstance(value, str) else value
            tokens[key] = label

        for token in re.split(r"\s+", task.text):
            stripped = token.strip("\"'()[],;:!?").rstrip(".")
            if stripped:
                add(stripped)
        for amount in _amount_tokens(task.text):
            add(amount)
        for scalar in _walk_scalars(task.params):
            add(scalar)
            if isinstance(scalar, int):
                add(scalar * 100)  # rupees -> paise
            elif isinstance(scalar, str):
                for amount in _amount_tokens(scalar):
                    add(amount)
        self._task[task.task_id] = tokens

    def register_value(self, value: str | int, label: Label) -> None:
        """Remember a result/extracted value so re-typing it cannot launder its label."""
        key: str | int = _norm(value) if isinstance(value, str) else value
        previous = self._exact.get(key)
        self._exact[key] = label if previous is None else join_all([previous, label])
        if isinstance(value, str) and len(value.strip()) >= MIN_SUBSTRING:
            self._substr.append((_norm(value), label))

    def register_tree(self, value: object, label: Label) -> None:
        for scalar in _walk_scalars(value):
            self.register_value(scalar, label)

    # --- lookup --------------------------------------------------------------------------
    def label_for(self, task_id: str, value: object) -> Label:
        if value is None or isinstance(value, bool | list | dict):
            return _CONSTANT  # no content of its own (empty containers, flags)
        if isinstance(value, int):
            found = self._task.get(task_id, {}).get(value) or self._exact.get(value)
            return found if found is not None else model_untrusted(task_id)
        if not isinstance(value, str):
            return model_untrusted(task_id)
        key = _norm(value)
        pii = Label.make(Level.TRUSTED_USER, tags=label_pii(value))
        exact = self._task.get(task_id, {}).get(key) or self._exact.get(key)
        if exact is not None:
            return join_all([exact, pii])
        hits = [label for text, label in self._substr if text in key]
        # planner-authored text around a registered value is of unknown origin: stay untrusted
        return join_all([*hits, model_untrusted(task_id), pii])


# --- handles ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class HandleMeta:
    kind: str  # "doc" | "var" | "voice"
    ref: str  # source ref id (document id, message set id, clip id) or parent handle
    op: str | None = None  # extractor name for derived vars
    injection_score: float = 0.0
    hidden_text: bool = False
    parent: str | None = None
    source_kind: str = "document"


class SessionHandles:
    """``$DOC_n`` (via ``HandleStore``) and ``$VAR_n`` storage with lineage metadata."""

    def __init__(self, registry: TaintRegistry) -> None:
        self._docs = HandleStore()
        self._vars: dict[str, Labeled[object]] = {}
        self._var_counter = 0
        self._meta: dict[str, HandleMeta] = {}
        self._registry = registry

    def put_doc(self, value: object, label: Label, meta: HandleMeta) -> str:
        handle = self._docs.put(Labeled.source(value, label))
        self._meta[handle.id] = meta
        return handle.id

    def get(self, handle_id: str) -> Labeled[object] | None:
        if handle_id in self._vars:
            return self._vars[handle_id]
        if handle_id.startswith("$DOC_"):
            try:
                return self._docs.reader().extract(OpaqueHandle(handle_id), lambda v: v)
            except (KeyError, ValueError):
                return None
        return None

    def meta(self, handle_id: str) -> HandleMeta | None:
        return self._meta.get(handle_id)

    def extract(
        self, handle_id: str, name: str, extractor: Callable[[object], object]
    ) -> tuple[str, Labeled[object]]:
        """Quarantined read: only this method dereferences a ``$DOC`` handle."""
        if not handle_id.startswith("$DOC_"):
            raise KeyError(handle_id)
        parent = self._docs.reader().extract(OpaqueHandle(handle_id), extractor)
        if parent.value is None:
            raise LookupError(f"field {name!r} not found")
        self._var_counter += 1
        var_id = f"$VAR_{self._var_counter}"
        self._vars[var_id] = parent
        pmeta = self._meta.get(handle_id)
        self._meta[var_id] = HandleMeta(
            kind="var",
            ref=pmeta.ref if pmeta else handle_id,
            op=name,
            injection_score=pmeta.injection_score if pmeta else 0.0,
            hidden_text=pmeta.hidden_text if pmeta else False,
            parent=handle_id,
            source_kind=pmeta.source_kind if pmeta else "document",
        )
        value = parent.value
        if isinstance(value, str | int) and not isinstance(value, bool):
            self._registry.register_value(value, parent.label)
        return var_id, parent

    def put_var(self, value: object, label: Label, meta: HandleMeta) -> str:
        self._var_counter += 1
        var_id = f"$VAR_{self._var_counter}"
        self._vars[var_id] = derive(lambda v: v, Labeled.source(value, label))
        self._meta[var_id] = meta
        return var_id


# --- hidden text / injection score -----------------------------------------------------------

_HIDDEN_STYLES = (
    re.compile(r"display\s*:\s*none", re.I),
    re.compile(r"visibility\s*:\s*hidden", re.I),
    re.compile(r"font-size\s*:\s*0*[01](?:\.\d+)?\s*(?:px|pt|em|rem|%)?\s*(?:;|\"|'|$)", re.I),
    re.compile(r"opacity\s*:\s*0(?:\.0+)?\s*(?:;|\"|'|$)", re.I),
)
_STYLE_ATTR = re.compile(r"style\s*=\s*(\"[^\"]*\"|'[^']*')", re.I)
_COLOR = re.compile(r"(?<![-\w])color\s*:\s*(#fff(?:fff)?|white)\b", re.I)
_BG = re.compile(r"background(?:-color)?\s*:\s*(#fff(?:fff)?|white)\b", re.I)
_INSTRUCTION = re.compile(
    r"ignore (?:all |the )?(?:previous|prior)|system note|instead|disregard|you must", re.I
)


def hidden_text_score(html: str) -> tuple[float, bool]:
    """Return ``(injection_score, hidden_text_found)`` for an HTML document."""
    hidden = False
    for style in _STYLE_ATTR.findall(html):
        if any(p.search(style + ";") for p in _HIDDEN_STYLES) or (
            _COLOR.search(style) and _BG.search(style)
        ):
            hidden = True
            break
    score = 0.9 if hidden else 0.0
    if _INSTRUCTION.search(_visible_text(html)) and hidden:
        score = 1.0
    return score, hidden


def _visible_text(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


# --- deterministic extractors ----------------------------------------------------------------


def extract_payee_vpa(content: object) -> object:
    text = _visible_text(str(content))
    m = re.search(r"Payee VPA\s*:\s*([A-Za-z0-9._-]+@[A-Za-z0-9._-]+)", text)
    return m.group(1) if m else None


def extract_amount_paise(content: object) -> object:
    text = _visible_text(str(content))
    m = re.search(r"Amount\s*:\s*(?:₹|Rs\.?|INR)?\s*(\d[\d,]*)(?:\.(\d{1,2}))?", text)
    if not m:
        return None
    whole = m.group(1).replace(",", "")
    frac = (m.group(2) or "0").ljust(2, "0")
    return int(whole) * 100 + int(frac)


def extract_invoice_id(content: object) -> object:
    text = _visible_text(str(content))
    m = re.search(r"Invoice Number\s*:\s*([A-Z]{2,5}-\d+)", text)
    return m.group(1) if m else None


EXTRACTORS: dict[str, Callable[[object], object]] = {
    "payee_vpa": extract_payee_vpa,
    "amount_paise": extract_amount_paise,
    "invoice_id": extract_invoice_id,
}
