"""YAML -> schema validation -> AST -> ``CompiledPolicy``. Errors are collected, with locations."""

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import get_args

import yaml
from pydantic import ValidationError

from trishul.contracts.calls import ToolCategory
from trishul.contracts.canonical import is_pointer, pointer_tokens
from trishul.contracts.decisions import RULE_ID_PATTERN, Decision, Stage
from trishul.contracts.labels import Level, SourceKind, Tag
from trishul.policy import ast
from trishul.policy.schema import PolicyFile

Path_ = tuple[str | int, ...]
Loc = tuple[int, int]
MAX_DEPTH = 64
COMPARE_OPS: dict[str, ast.CompareOp] = {o: o for o in get_args(ast.CompareOp)}
SOURCE_KINDS: dict[str, SourceKind] = {k: k for k in get_args(SourceKind)}


@dataclass(frozen=True)
class PolicyCompileError:
    path: str
    line: int
    col: int
    message: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}:{self.col}: {self.message}"


class PolicyCompileFailure(Exception):
    def __init__(self, errors: Sequence[PolicyCompileError]) -> None:
        self.errors = tuple(errors)
        super().__init__("\n".join(str(e) for e in self.errors))


# --- YAML loading with positions --------------------------------------------------------


@dataclass
class _Doc:
    file: str
    data: object = None
    locs: dict[Path_, Loc] = field(default_factory=dict)
    errors: list[PolicyCompileError] = field(default_factory=list)

    def err(self, path: Path_, message: str) -> None:
        line, col = self.loc(path)
        self.errors.append(PolicyCompileError(self.file, line, col, message))

    def loc(self, path: Path_) -> Loc:
        for end in range(len(path), -1, -1):
            if path[:end] in self.locs:
                return self.locs[path[:end]]
        return (1, 1)


def _mark(node: yaml.Node) -> Loc:
    return (node.start_mark.line + 1, node.start_mark.column + 1)


def _walk(node: yaml.Node, path: Path_, doc: _Doc, loader: yaml.SafeLoader, depth: int) -> object:
    doc.locs.setdefault(path, _mark(node))
    if depth > MAX_DEPTH:
        doc.err(path, "document nested too deeply")
        return None
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_object(node, deep=True)
    if isinstance(node, yaml.SequenceNode):
        return [
            _walk(item, (*path, i), doc, loader, depth + 1) for i, item in enumerate(node.value)
        ]
    if isinstance(node, yaml.MappingNode):
        result: dict[str, object] = {}
        for key_node, value_node in node.value:
            key = (
                loader.construct_object(key_node, deep=True)
                if isinstance(key_node, yaml.ScalarNode)
                else None
            )
            if not isinstance(key, str):
                doc.locs.setdefault((*path, "?"), _mark(key_node))
                doc.err((*path, "?"), "mapping keys must be strings")
                continue
            if key in result:
                doc.locs[(*path, key)] = _mark(key_node)
                doc.err((*path, key), f"duplicate key '{key}'")
                continue
            result[key] = _walk(value_node, (*path, key), doc, loader, depth + 1)
            doc.locs[(*path, key)] = _mark(key_node)
        return result
    doc.err(path, "unsupported YAML node")
    return None


def _load(file: str, text: str) -> _Doc:
    doc = _Doc(file)
    loader = yaml.SafeLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            doc.errors.append(PolicyCompileError(file, 1, 1, "empty policy document"))
        else:
            doc.data = _walk(node, (), doc, loader, 0)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark
        line, col = (mark.line + 1, mark.column + 1) if mark else (1, 1)
        doc.errors.append(PolicyCompileError(file, line, col, f"YAML error: {exc.problem}"))
    except yaml.YAMLError as exc:
        doc.errors.append(PolicyCompileError(file, 1, 1, f"YAML error: {exc}"))
    finally:
        loader.dispose()
    return doc


# --- predicate parsing ------------------------------------------------------------------


@dataclass
class _PathRef:
    pointer: str
    path: Path_


@dataclass
class _ParsedRule:
    rule: ast.Rule
    path: Path_
    doc: _Doc
    path_refs: list[_PathRef] = field(default_factory=list)
    tool_refs: list[tuple[str, Path_]] = field(default_factory=list)
    categories: set[ToolCategory] = field(default_factory=set)


class _Parser:
    def __init__(self, doc: _Doc) -> None:
        self.doc = doc
        self.path_refs: list[_PathRef] = []
        self.tool_refs: list[tuple[str, Path_]] = []
        self.categories: set[ToolCategory] = set()
        self.ok = True

    def fail(self, path: Path_, message: str) -> None:
        self.ok = False
        self.doc.err(path, message)

    # helpers -----------------------------------------------------------------------
    def _str(self, data: object, path: Path_, what: str) -> str | None:
        if isinstance(data, str) and data:
            return data
        self.fail(path, f"{what} must be a non-empty string")
        return None

    def _ptr(self, data: object, path: Path_, what: str = "arg") -> str | None:
        if isinstance(data, str) and is_pointer(data):
            self.path_refs.append(_PathRef(data, path))
            return data
        self.fail(path, f"{what} must be a JSON pointer such as /payee_vpa")
        return None

    def _fields(self, data: object, path: Path_, required: set[str]) -> dict[str, object] | None:
        if not isinstance(data, dict):
            self.fail(path, f"expected a mapping with keys {sorted(required)}")
            return None
        good = True
        for key in data:
            if key not in required:
                self.fail((*path, key), f"unknown key '{key}'")
                good = False
        for key in sorted(required - set(data)):
            self.fail(path, f"missing key '{key}'")
            good = False
        return data if good else None

    def _enum[E](self, data: object, path: Path_, options: dict[str, E], what: str) -> E | None:
        if isinstance(data, str) and data in options:
            return options[data]
        self.fail(path, f"{what} must be one of {sorted(options)}")
        return None

    # predicates --------------------------------------------------------------------
    def parse(self, data: object, path: Path_) -> ast.Predicate | None:
        if not isinstance(data, dict) or len(data) != 1:
            self.fail(path, "predicate must be a mapping with exactly one key")
            return None
        ((key, body),) = data.items()
        handler = self._handlers().get(key)
        if handler is None:
            self.fail((*path, key), f"unknown predicate '{key}'")
            return None
        return handler(body, (*path, key))

    def _handlers(self) -> dict[str, Callable[[object, Path_], ast.Predicate | None]]:
        return {
            "const": self._const,
            "all": self._all,
            "any": self._any,
            "not": self._not,
            "tool": self._tool,
            "tool_category": self._category,
            "arg_exists": self._exists,
            "arg_compare": self._compare,
            "label_at_least": self._level,
            "label_has_tag": self._tag,
            "source_kind_in": self._kinds,
            "purpose_is": self._purpose,
            "consent_covers": self._consent,
            "mandate_present": self._mandate_present,
            "mandate_covers": self._mandate_covers,
            "approval_present": self._approval,
            "amount_exceeds": self._amount,
        }

    def _const(self, body: object, path: Path_) -> ast.Predicate | None:
        if isinstance(body, bool):
            return ast.Const(value=body)
        self.fail(path, "const must be true or false")
        return None

    def _items(self, body: object, path: Path_) -> tuple[ast.Predicate, ...] | None:
        if not isinstance(body, list) or not body:
            self.fail(path, "expected a non-empty list of predicates")
            return None
        parsed = [self.parse(item, (*path, i)) for i, item in enumerate(body)]
        return None if any(p is None for p in parsed) else tuple(p for p in parsed if p)

    def _all(self, body: object, path: Path_) -> ast.Predicate | None:
        items = self._items(body, path)
        return ast.All(items=items) if items is not None else None

    def _any(self, body: object, path: Path_) -> ast.Predicate | None:
        items = self._items(body, path)
        return ast.Any(items=items) if items is not None else None

    def _not(self, body: object, path: Path_) -> ast.Predicate | None:
        item = self.parse(body, path)
        return ast.Not(item=item) if item is not None else None

    def _tool(self, body: object, path: Path_) -> ast.Predicate | None:
        name = self._str(body, path, "tool")
        if name is None:
            return None
        self.tool_refs.append((name, path))
        return ast.ToolIs(tool=name)

    def _category(self, body: object, path: Path_) -> ast.Predicate | None:
        raw = body if isinstance(body, list) else [body]
        options = {c.value: c for c in ToolCategory}
        cats = [self._enum(v, path, options, "tool_category") for v in raw]
        if not raw or any(c is None for c in cats):
            return None
        found = {c for c in cats if c is not None}
        self.categories |= found
        return ast.ToolCategoryIn(categories=tuple(sorted(found)))

    def _exists(self, body: object, path: Path_) -> ast.Predicate | None:
        ptr = self._ptr(body, path)
        return ast.ArgExists(path=ptr) if ptr else None

    def _compare(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"arg", "op", "value"})
        if f is None:
            return None
        ptr = self._ptr(f["arg"], (*path, "arg"))
        op = self._enum(f["op"], (*path, "op"), COMPARE_OPS, "op")
        value = f["value"]
        if isinstance(value, float):
            self.fail((*path, "value"), "floats are not allowed; use integer minor units")
            return None
        if not (value is None or isinstance(value, bool | int | str)):
            self.fail((*path, "value"), "value must be a string, integer, boolean or null")
            return None
        if ptr is None or op is None:
            return None
        return ast.ArgCompare(path=ptr, op=op, value=value)

    def _level(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"arg", "level"})
        if f is None:
            return None
        ptr = self._ptr(f["arg"], (*path, "arg"))
        level = self._enum(f["level"], (*path, "level"), dict(Level.__members__), "level")
        return ast.LabelAtLeast(path=ptr, level=level) if ptr and level is not None else None

    def _tag(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"arg", "tag"})
        if f is None:
            return None
        ptr = self._ptr(f["arg"], (*path, "arg"))
        tag = self._enum(f["tag"], (*path, "tag"), {t.value: t for t in Tag}, "tag")
        return ast.LabelHasTag(path=ptr, tag=tag) if ptr and tag else None

    def _kinds(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"arg", "kinds"})
        if f is None:
            return None
        ptr = self._ptr(f["arg"], (*path, "arg"))
        raw = f["kinds"]
        if not isinstance(raw, list) or not raw:
            self.fail((*path, "kinds"), "kinds must be a non-empty list")
            return None
        kinds = [
            self._enum(k, (*path, "kinds", i), SOURCE_KINDS, "source kind")
            for i, k in enumerate(raw)
        ]
        if ptr is None or any(k is None for k in kinds):
            return None
        return ast.SourceKindIn(
            path=ptr,
            kinds=tuple(sorted({k for k in kinds if k})),
        )

    def _purpose(self, body: object, path: Path_) -> ast.Predicate | None:
        purpose = self._str(body, path, "purpose")
        return ast.PurposeIs(purpose=purpose) if purpose else None

    def _consent(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"purpose", "fields_arg"})
        if f is None:
            return None
        purpose = self._str(f["purpose"], (*path, "purpose"), "purpose")
        ptr = self._ptr(f["fields_arg"], (*path, "fields_arg"), "fields_arg")
        return ast.ConsentCovers(purpose=purpose, fields_path=ptr) if purpose and ptr else None

    def _mandate_present(self, body: object, path: Path_) -> ast.Predicate | None:
        if body is True:
            return ast.MandatePresent()
        self.fail(path, "mandate_present must be true")
        return None

    def _mandate_covers(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"amount_arg", "payee_arg"})
        if f is None:
            return None
        amount = self._ptr(f["amount_arg"], (*path, "amount_arg"), "amount_arg")
        payee = self._ptr(f["payee_arg"], (*path, "payee_arg"), "payee_arg")
        if amount and payee:
            return ast.MandateCovers(amount_path=amount, payee_path=payee)
        return None

    def _approval(self, body: object, path: Path_) -> ast.Predicate | None:
        raw = body["scope"] if isinstance(body, dict) and set(body) == {"scope"} else body
        scope = self._str(raw, path, "approval scope")
        return ast.ApprovalPresent(scope=scope) if scope else None

    def _amount(self, body: object, path: Path_) -> ast.Predicate | None:
        f = self._fields(body, path, {"arg", "cap_paise"})
        if f is None:
            return None
        ptr = self._ptr(f["arg"], (*path, "arg"))
        cap = f["cap_paise"]
        if isinstance(cap, bool) or not isinstance(cap, int) or cap < 0:
            self.fail((*path, "cap_paise"), "cap_paise must be a non-negative integer")
            return None
        return ast.AmountExceeds(path=ptr, cap_paise=cap) if ptr else None


# --- file / merge -----------------------------------------------------------------------


def _schema_errors(doc: _Doc, exc: ValidationError) -> None:
    for e in exc.errors(include_input=False, include_url=False):
        loc = tuple(e["loc"])
        doc.err(loc, f"{'.'.join(map(str, loc)) or '<root>'}: {e['msg']}")


@dataclass
class _FileResult:
    doc: _Doc
    policy_id: str
    tools: dict[str, tuple[ast.ToolSpec, Path_]]
    rules: list[_ParsedRule]


def _compile_file(name: str, text: str) -> tuple[_FileResult | None, _Doc]:
    doc = _load(name, text)
    if doc.errors:
        return None, doc
    try:
        source = PolicyFile.model_validate(doc.data)
    except ValidationError as exc:
        _schema_errors(doc, exc)
        return None, doc
    tools: dict[str, tuple[ast.ToolSpec, Path_]] = {
        tname: (
            ast.ToolSpec(
                category=ToolCategory(t.category),
                args={a: ast.ArgSpec(type=s.type, required=s.required) for a, s in t.args.items()},
            ),
            ("tools", tname),
        )
        for tname, t in source.tools.items()
    }
    rules: list[_ParsedRule] = []
    stages = {s.value: s for s in Stage}
    for i, r in enumerate(source.rules):
        base: Path_ = ("rules", i)
        parser = _Parser(doc)
        if not re.fullmatch(RULE_ID_PATTERN, r.id):
            parser.fail((*base, "id"), f"rule id must match {RULE_ID_PATTERN}")
        stage = parser._enum(r.stage, (*base, "stage"), stages, "stage")
        then: Decision | None = None
        if r.then == "ALLOW":
            parser.fail((*base, "then"), "rules may only escalate: 'then' must be STEP_UP or DENY")
        else:
            then = parser._enum(
                r.then,
                (*base, "then"),
                {"STEP_UP": Decision.STEP_UP, "DENY": Decision.DENY},
                "then",
            )
        when = parser.parse(r.when, (*base, "when"))
        if not r.explain.strip():
            parser.fail((*base, "explain"), "explain must not be empty")
        if parser.ok and stage and then and when:
            rule = ast.Rule(id=r.id, stage=stage, then=then, explain=r.explain, when=when)
            rules.append(
                _ParsedRule(rule, base, doc, parser.path_refs, parser.tool_refs, parser.categories)
            )
    return _FileResult(doc, source.id, tools, rules), doc


def _check_references(pr: _ParsedRule, tools: dict[str, ast.ToolSpec]) -> None:
    """Paths must name an arg declared by some tool the rule can apply to; tools must exist."""
    named = {n for n, _ in pr.tool_refs if n in tools}
    for name, path in pr.tool_refs:
        if name not in tools:
            pr.doc.err(path, f"rule '{pr.rule.id}' references undeclared tool '{name}'")
    candidates = named | {n for n, t in tools.items() if t.category in pr.categories}
    if not pr.tool_refs and not pr.categories:
        candidates = set(tools)
    for ref in pr.path_refs:
        arg = pointer_tokens(ref.pointer)[0]
        if not any(arg in tools[n].args for n in candidates):
            pr.doc.err(
                ref.path,
                f"path '{ref.pointer}' is not an argument declared by any tool this rule "
                f"can apply to",
            )


def compile_sources(sources: Sequence[tuple[str, str]]) -> ast.CompiledPolicy:
    """Compile ``(name, yaml_text)`` pairs into one policy. Raises ``PolicyCompileFailure``."""
    if not sources:
        raise PolicyCompileFailure([PolicyCompileError("<input>", 1, 1, "no policy files given")])
    results: list[_FileResult] = []
    errors: list[PolicyCompileError] = []
    for name, text in sorted(sources, key=lambda s: s[0]):
        result, doc = _compile_file(name, text)
        if result is None:
            errors.extend(doc.errors)
        else:
            results.append(result)

    tools: dict[str, ast.ToolSpec] = {}
    tool_origin: dict[str, str] = {}
    rules: dict[str, _ParsedRule] = {}
    for res in results:
        for tname, (spec, path) in res.tools.items():
            if tname in tools and tools[tname] != spec:
                res.doc.err(
                    path,
                    f"tool '{tname}' conflicts with its definition in {tool_origin[tname]}",
                )
            tools.setdefault(tname, spec)
            tool_origin.setdefault(tname, res.doc.file)
        for pr in res.rules:
            if pr.rule.id in rules:
                first = rules[pr.rule.id].doc.file
                res.doc.err(
                    (*pr.path, "id"),
                    f"duplicate rule id '{pr.rule.id}' (first defined in {first})",
                )
            else:
                rules[pr.rule.id] = pr
    for res in results:
        for pr in res.rules:
            if rules.get(pr.rule.id) is pr:
                _check_references(pr, tools)
    errors += [e for res in results for e in res.doc.errors]
    if errors:
        raise PolicyCompileFailure(errors)
    policy_id = "+".join(sorted({r.policy_id for r in results}))
    return ast.CompiledPolicy.create(policy_id, tools, [p.rule for p in rules.values()])


def expand_paths(paths: Sequence[Path]) -> list[Path]:
    """Directories expand to their ``*.yaml`` / ``*.yml`` files (sorted, non-recursive)."""
    files: list[Path] = []
    for p in paths:
        if p.is_dir():
            files.extend(sorted(x for x in p.iterdir() if x.suffix in (".yaml", ".yml")))
        else:
            files.append(p)
    return files


def compile_files(paths: Sequence[Path]) -> ast.CompiledPolicy:
    sources: list[tuple[str, str]] = []
    errors: list[PolicyCompileError] = []
    for p in expand_paths(paths):
        try:
            sources.append((str(p), p.read_text(encoding="utf-8")))
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(PolicyCompileError(str(p), 1, 1, f"cannot read file: {exc}"))
    if errors:
        raise PolicyCompileFailure(errors)
    return compile_sources(sources)
