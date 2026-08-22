"""Turn JavaScript / TypeScript source into the same IR as the Python parser.

Owner: Member 5 (Prove + Integrations).

There is no JavaScript AST in the Python standard library, and pulling in
tree-sitter or a Node process would break the "simple scripts, no heavy
frameworks" rule. So this is a line scanner: it reads the file one line at a
time, tracks brace depth to know which function it is inside, and uses a
handful of regular expressions to pull out assignments and calls.

WHAT IT HANDLES (documented honestly, and repeated in docs/qa.md):
  * function declarations, arrow functions, Express route handlers
  * `const x = <expression>` and `x = <expression>`
  * calls with their arguments, including nested ones
  * template literals and `+` concatenation as taint carriers

WHAT IT DOES NOT HANDLE:
  * a call whose arguments span several lines
  * destructuring beyond the simple `const { a, b } = req.query` form
  * classes and object-method shorthand
  * comments containing code-like text (we strip // and /* */ first)

Those limits are acceptable because Python is our primary target language and
Semgrep covers JavaScript in the baseline comparison. Being explicit about
them is better than pretending the coverage is complete.
"""

from __future__ import annotations

import re

from . import rules
from .cpg import CPG, Call, Expr, Function, Stmt

# `function name(a, b) {`  /  `async function name(a) {`
RE_FUNCTION = re.compile(r"\b(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)")
# `const name = (a, b) => {`  /  `let name = async (a) => {`
RE_ARROW_NAMED = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>")
# `app.get('/path', (req, res) => {`   /  `router.post("/p", async function (req, res) {`
RE_ROUTE = re.compile(
    r"\b(app|router|server|api)\s*\.\s*(get|post|put|delete|patch|all|use)\s*\(\s*"
    r"""['"`]([^'"`]*)['"`]\s*,\s*(?:async\s*)?(?:\(([^)]*)\)|(\w+))\s*(?:=>|\{|function)""")
# `const x = ...`  /  `x = ...`  (not `==` or `=>`)
RE_ASSIGN = re.compile(r"^\s*(?:const|let|var)?\s*([\w.]+)\s*=(?![=>])\s*(.+?);?\s*$")
# `const { a, b } = req.query;`
RE_DESTRUCTURE = re.compile(r"^\s*(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+?);?\s*$")
# a call: `name(` or `obj.method(`
RE_CALL = re.compile(r"([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*\(")
# an identifier that is not a keyword
RE_IDENT = re.compile(r"\b([A-Za-z_$][\w$]*)\b")

JS_KEYWORDS = {
    "const", "let", "var", "function", "return", "if", "else", "for", "while",
    "new", "await", "async", "true", "false", "null", "undefined", "this",
    "typeof", "instanceof", "in", "of", "try", "catch", "finally", "throw",
    "class", "extends", "import", "export", "from", "default", "case", "switch",
    "break", "continue", "do", "delete", "void", "yield", "static",
}


class JavaScriptParser:
    """Parses one JS/TS file at a time and appends to a shared CPG."""

    LANG = "javascript"

    def __init__(self, cpg: CPG) -> None:
        self.cpg = cpg

    # ------------------------------------------------------------------ api

    def parse_file(self, rel_path: str, source: str) -> tuple[list[Function], str | None]:
        self.file = rel_path
        lines = _strip_comments(source).splitlines()

        module_node = self.cpg.add_node("MODULE", rel_path, rel_path, 1)
        functions: list[Function] = []

        # `open_functions` is a stack of (function, brace_depth_at_which_it_ends).
        open_functions: list[tuple[Function, int]] = []
        depth = 0
        module_fn = Function(name="<module>", file=rel_path, line=1, end_line=len(lines),
                             lang=self.LANG, node_id=module_node.id)

        for index, raw in enumerate(lines):
            line_no = index + 1
            line = raw.strip()

            started = self._maybe_start_function(line, line_no, module_node.id)
            if started is not None:
                # A function opens on this line; it closes when depth returns here.
                open_functions.append((started, depth))
                functions.append(started)
                depth += raw.count("{") - raw.count("}")
                continue

            target_fn = open_functions[-1][0] if open_functions else module_fn
            statement = self._build_stmt(line, line_no, target_fn)
            if statement is not None:
                target_fn.body.append(statement)

            depth += raw.count("{") - raw.count("}")
            while open_functions and depth <= open_functions[-1][1]:
                closed, _ = open_functions.pop()
                closed.end_line = line_no

        if module_fn.body:
            functions.append(module_fn)
        return functions, None

    # ------------------------------------------------------------- functions

    def _maybe_start_function(self, line: str, line_no: int, parent_id: int) -> Function | None:
        route = RE_ROUTE.search(line)
        if route:
            obj, method, path, inline_params, named_handler = route.groups()
            params = _split_params(inline_params or "")
            name = f"{obj}.{method} {path}" if inline_params else (named_handler or "handler")
            fn = self._new_function(name, params, line_no, parent_id,
                                    route_path=path, methods=[method.upper()])
            # An `app.get(...)` line often also contains the first statement.
            return fn

        arrow = RE_ARROW_NAMED.search(line)
        if arrow:
            return self._new_function(arrow.group(1), _split_params(arrow.group(2)),
                                      line_no, parent_id)

        declared = RE_FUNCTION.search(line)
        if declared:
            return self._new_function(declared.group(1), _split_params(declared.group(2)),
                                      line_no, parent_id)
        return None

    def _new_function(self, name: str, params: list[str], line_no: int, parent_id: int,
                      route_path: str = "", methods: list[str] | None = None) -> Function:
        fn_node = self.cpg.add_node("FUNCTION", name, self.file, line_no, f"function {name}(...)")
        self.cpg.add_edge(parent_id, fn_node.id, "AST")
        for param in params:
            param_node = self.cpg.add_node("PARAM", param, self.file, line_no)
            self.cpg.add_edge(fn_node.id, param_node.id, "AST")
        if route_path:
            route_node = self.cpg.add_node("ROUTE", route_path, self.file, line_no,
                                           f"{'|'.join(methods or [])} {route_path}")
            self.cpg.add_edge(route_node.id, fn_node.id, "CALL")
        return Function(name=name, file=self.file, line=line_no, end_line=line_no,
                        lang=self.LANG, params=params, route_path=route_path,
                        route_methods=methods or [], node_id=fn_node.id)

    # ------------------------------------------------------------ statements

    def _build_stmt(self, line: str, line_no: int, fn: Function) -> Stmt | None:
        if not line or line in ("{", "}", "});", ")", "};"):
            return None

        destructured = RE_DESTRUCTURE.match(line)
        if destructured:
            names = [n.strip().split(":")[-1].strip()
                     for n in destructured.group(1).split(",") if n.strip()]
            value = self._build_expr(destructured.group(2), line_no)
            self._register(fn, "ASSIGN", ",".join(names), line_no, line)
            return Stmt(kind="assign", line=line_no, code=line, targets=names, value=value)

        if line.startswith("if") or line.startswith("} else if"):
            test = self._build_expr(_inside_parens(line), line_no)
            self._register(fn, "IF", "if", line_no, line)
            return Stmt(kind="if", line=line_no, code=line, test=test,
                        always_false="if (false)" in line.replace(" ", " "))

        if line.startswith("return"):
            value = self._build_expr(line[len("return"):].strip().rstrip(";"), line_no)
            self._register(fn, "RETURN", "return", line_no, line)
            return Stmt(kind="return", line=line_no, code=line, value=value)

        assigned = RE_ASSIGN.match(line)
        if assigned and "(" not in assigned.group(1):
            target = assigned.group(1)
            value = self._build_expr(assigned.group(2), line_no)
            self._register(fn, "ASSIGN", target, line_no, line)
            return Stmt(kind="assign", line=line_no, code=line, targets=[target], value=value)

        if "(" in line:
            value = self._build_expr(line.rstrip(";"), line_no)
            if value.calls or value.sources:
                self._register(fn, "CALL", "expr", line_no, line)
                return Stmt(kind="expr", line=line_no, code=line, value=value)
        return None

    def _register(self, fn: Function, kind: str, name: str, line_no: int, code: str) -> None:
        node = self.cpg.add_node(kind, name, self.file, line_no, code[:200])
        self.cpg.add_edge(fn.node_id, node.id, "AST")

    # ----------------------------------------------------------- expressions

    def _build_expr(self, text: str, line_no: int) -> Expr:
        expr = Expr(code=text.strip())
        if not text:
            return expr

        # 1. Sources. `req.query.id` and `req.query["id"]` both start with req.query.
        for rule in rules.SOURCES:
            if rule["lang"] != self.LANG:
                continue
            if re.search(r"\b" + re.escape(rule["pattern"]) + r"\b", text):
                expr.sources.append(rule["pattern"])

        # 2. Calls, with their arguments.
        for match in RE_CALL.finditer(text):
            name = re.sub(r"\s+", "", match.group(1))
            if name in JS_KEYWORDS:
                continue
            args_text = _balanced_args(text, match.end() - 1)
            call = Call(name=name, line=line_no, code=f"{name}({args_text})")
            for argument in _split_args(args_text):
                call.args.append(self._build_expr_shallow(argument, line_no))
            expr.calls.append(call)

        # 3. Plain identifiers read by this expression.
        #    String literals are blanked out first so words inside them are not
        #    mistaken for variables -- but `${...}` holes in a template literal
        #    ARE real code, so we add their contents back before scanning.
        #    Without this, `db.query(`... id = ${id}`)` looks like it reads
        #    nothing and the SQL injection is missed entirely.
        interpolations = " ".join(re.findall(r"\$\{([^}]*)\}", text))
        scannable = _without_strings(text) + " " + interpolations
        for match in RE_IDENT.finditer(scannable):
            name = match.group(1)
            if name in JS_KEYWORDS:
                continue
            # Skip the name of a call and property accesses like `.length`.
            following = text[match.end():match.end() + 1]
            preceding = text[max(0, match.start() - 1):match.start()]
            if following == "(" or preceding == ".":
                continue
            expr.vars.append(name)

        expr.vars = list(dict.fromkeys(expr.vars))
        expr.sources = list(dict.fromkeys(expr.sources))
        expr.only_literal = not expr.vars and not expr.sources and not expr.calls
        return expr

    def _build_expr_shallow(self, text: str, line_no: int) -> Expr:
        """Build an argument expression. Same code path -- kept separate for clarity."""
        return self._build_expr(text, line_no)


# --------------------------------------------------------------------------
# Small text helpers. Each one does exactly one thing.
# --------------------------------------------------------------------------


def _strip_comments(source: str) -> str:
    """Remove /* block */ and // line comments so they cannot look like code."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    cleaned_lines = []
    for line in source.splitlines():
        # Only strip // when it is not inside a string or a URL like http://
        without_strings = _without_strings(line)
        index = without_strings.find("//")
        if index != -1 and not without_strings[:index].rstrip().endswith(":"):
            line = line[:index]
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)


def _without_strings(text: str) -> str:
    """Blank out string literals so identifiers inside them are not counted."""
    return re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", lambda m: m.group(1) * len(m.group(0)), text)


def _split_params(text: str) -> list[str]:
    return [p.strip().split("=")[0].strip() for p in text.split(",") if p.strip()]


def _inside_parens(line: str) -> str:
    start = line.find("(")
    if start == -1:
        return ""
    return _balanced_args(line, start)


def _balanced_args(text: str, open_index: int) -> str:
    """Given the index of a '(', return the text up to its matching ')'."""
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1:index]
    return text[open_index + 1:]


def _split_args(text: str) -> list[str]:
    """Split `a, f(b, c), "d,e"` into three arguments, respecting nesting."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    quote = ""
    for char in text:
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            continue
        if char in "\"'`":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth -= 1
            current.append(char)
        elif char == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current:
        args.append("".join(current).strip())
    return [a for a in args if a]
