"""Turn Python source into the IR that Stage 2 walks.

Owner: Member 1 (Prepare / CPG).

We use the standard library `ast` module. That means:
  * no pip install for the code being scanned,
  * no virtualenv for it,
  * no import of it (we never execute the target code -- we only read it).

That is what "build-free" means in the problem statement, and it is why a
scan of an unknown repository takes seconds instead of minutes.
"""

from __future__ import annotations

import ast

from . import rules
from .cpg import CPG, Call, Expr, Function, Stmt

# Decorators that register an HTTP route. Anything they decorate is directly
# reachable by an attacker, which matters a lot in Stage 3.
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "options", "head"}


class PythonParser:
    """Parses one file at a time and appends to a shared CPG."""

    LANG = "python"

    def __init__(self, cpg: CPG) -> None:
        self.cpg = cpg

    # ------------------------------------------------------------------ api

    def parse_file(self, rel_path: str, source: str) -> tuple[list[Function], str | None]:
        """Return (functions, error). `error` is set when the file will not parse."""
        try:
            tree = ast.parse(source, filename=rel_path)
        except SyntaxError as exc:
            return [], f"SyntaxError line {exc.lineno}: {exc.msg}"

        self.source = source
        self.file = rel_path

        module_node = self.cpg.add_node("MODULE", rel_path, rel_path, 1)
        functions: list[Function] = []

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(self._build_function(node, module_node.id))
            elif isinstance(node, ast.ClassDef):
                for member in node.body:
                    if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        functions.append(
                            self._build_function(member, module_node.id, class_name=node.name))

        # Module-level code is analysed too -- plenty of scripts put their
        # vulnerability straight in the module body.
        top_level = [n for n in tree.body
                     if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        if top_level:
            body = self._build_body(top_level, module_node.id)
            if body:
                functions.append(Function(
                    name="<module>", file=rel_path, line=1,
                    end_line=len(source.splitlines()), lang=self.LANG,
                    body=body, node_id=module_node.id,
                ))

        return functions, None

    # ------------------------------------------------------------- functions

    def _build_function(self, node, parent_id: int, class_name: str = "") -> Function:
        name = f"{class_name}.{node.name}" if class_name else node.name
        end_line = getattr(node, "end_lineno", node.lineno) or node.lineno

        fn_node = self.cpg.add_node("FUNCTION", name, self.file, node.lineno, f"def {node.name}(...)")
        self.cpg.add_edge(parent_id, fn_node.id, "AST")

        params = [a.arg for a in node.args.args + node.args.kwonlyargs]
        if node.args.vararg:
            params.append(node.args.vararg.arg)
        if node.args.kwarg:
            params.append(node.args.kwarg.arg)
        params = [p for p in params if p not in ("self", "cls")]

        for param in params:
            param_node = self.cpg.add_node("PARAM", param, self.file, node.lineno)
            self.cpg.add_edge(fn_node.id, param_node.id, "AST")

        route_path, methods = self._route_info(node.decorator_list)
        if route_path:
            route_node = self.cpg.add_node(
                "ROUTE", route_path, self.file, node.lineno,
                f"{'|'.join(methods)} {route_path}")
            self.cpg.add_edge(route_node.id, fn_node.id, "CALL")

        return Function(
            name=name, file=self.file, line=node.lineno, end_line=end_line,
            lang=self.LANG, params=params, body=self._build_body(node.body, fn_node.id),
            route_path=route_path, route_methods=methods, node_id=fn_node.id,
        )

    def _route_info(self, decorators: list) -> tuple[str, list[str]]:
        """Read @app.route('/x', methods=['POST']) and friends."""
        for decorator in decorators:
            call = decorator if isinstance(decorator, ast.Call) else None
            target = call.func if call else decorator
            attr = target.attr if isinstance(target, ast.Attribute) else ""
            if attr not in ROUTE_DECORATORS:
                continue

            path = ""
            methods = ["GET"] if attr == "route" else [attr.upper()]
            if call:
                if call.args and isinstance(call.args[0], ast.Constant):
                    path = str(call.args[0].value)
                for keyword in call.keywords:
                    if keyword.arg == "methods" and isinstance(keyword.value, (ast.List, ast.Tuple)):
                        found = [e.value for e in keyword.value.elts
                                 if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                        if found:
                            methods = found
            return path or "/", methods
        return "", []

    # ------------------------------------------------------------ statements

    def _build_body(self, nodes: list, parent_id: int) -> list[Stmt]:
        statements: list[Stmt] = []
        previous_node_id: int | None = None
        for node in nodes:
            built = self._build_stmt(node, parent_id)
            for stmt in built:
                statements.append(stmt)
            # FLOW edges make the CPG a control-flow graph, not just a tree.
            node_id = getattr(node, "_cpg_id", None)
            if previous_node_id is not None and node_id is not None:
                self.cpg.add_edge(previous_node_id, node_id, "FLOW")
            if node_id is not None:
                previous_node_id = node_id
        return statements

    def _build_stmt(self, node, parent_id: int) -> list[Stmt]:
        line = getattr(node, "lineno", 0)
        code = self._segment(node)

        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    targets.extend(self._target_names(target))
            else:
                targets.extend(self._target_names(node.target))

            if node.value is None:
                return []
            value = self._build_expr(node.value)
            # `x += y` keeps whatever taint x already had, so read x too.
            if isinstance(node, ast.AugAssign) and targets:
                value.vars = list(dict.fromkeys(value.vars + [targets[0]]))
                value.only_literal = False

            self._register(node, parent_id, "ASSIGN", ",".join(targets) or "_", line, code)
            return [Stmt(kind="assign", line=line, code=code, targets=targets, value=value)]

        if isinstance(node, ast.Expr):
            value = self._build_expr(node.value)
            self._register(node, parent_id, "CALL", "expr", line, code)
            return [Stmt(kind="expr", line=line, code=code, value=value)]

        if isinstance(node, ast.Return):
            value = self._build_expr(node.value) if node.value is not None else None
            self._register(node, parent_id, "RETURN", "return", line, code)
            return [Stmt(kind="return", line=line, code=code, value=value)]

        if isinstance(node, (ast.If, ast.While)):
            first_line = code.split("\n")[0]
            self._register(node, parent_id, "IF", "if", line, first_line)
            node_id = node._cpg_id
            test = self._build_expr(node.test)
            return [Stmt(
                kind="if", line=line, code=first_line, test=test,
                body=self._build_body(node.body, node_id),
                orelse=self._build_body(node.orelse, node_id),
                always_false=self._is_always_false(node.test),
            )]

        if isinstance(node, (ast.For, ast.AsyncFor)):
            first_line = code.split("\n")[0]
            self._register(node, parent_id, "LOOP", "for", line, first_line)
            node_id = node._cpg_id
            targets = self._target_names(node.target)
            iterated = self._build_expr(node.iter)
            # `for item in tainted_list:` taints item.
            statements = [Stmt(kind="assign", line=line, code=first_line,
                               targets=targets, value=iterated)]
            statements.append(Stmt(kind="loop", line=line, code=first_line,
                                   body=self._build_body(node.body, node_id)))
            return statements

        if isinstance(node, ast.Try):
            out: list[Stmt] = []
            out.extend(self._build_body(node.body, parent_id))
            for handler in node.handlers:
                out.extend(self._build_body(handler.body, parent_id))
            out.extend(self._build_body(node.finalbody, parent_id))
            return out

        if isinstance(node, (ast.With, ast.AsyncWith)):
            out = []
            for item in node.items:
                if item.optional_vars is not None:
                    names = self._target_names(item.optional_vars)
                    out.append(Stmt(kind="assign", line=line, code=code, targets=names,
                                    value=self._build_expr(item.context_expr)))
                else:
                    out.append(Stmt(kind="expr", line=line, code=code,
                                    value=self._build_expr(item.context_expr)))
            out.extend(self._build_body(node.body, parent_id))
            return out

        return []

    def _register(self, node, parent_id: int, kind: str, name: str, line: int, code: str) -> None:
        cpg_node = self.cpg.add_node(kind, name, self.file, line, code[:200])
        self.cpg.add_edge(parent_id, cpg_node.id, "AST")
        node._cpg_id = cpg_node.id

    # ----------------------------------------------------------- expressions

    def _build_expr(self, node) -> Expr:
        """Flatten an expression into: variables read, sources hit, calls made."""
        expr = Expr(code=self._segment(node))
        self._walk_expr(node, expr)
        expr.vars = list(dict.fromkeys(expr.vars))
        expr.sources = list(dict.fromkeys(expr.sources))
        expr.only_literal = not expr.vars and not expr.sources and not expr.calls
        return expr

    def _walk_expr(self, node, expr: Expr) -> None:
        if node is None:
            return

        if isinstance(node, ast.Name):
            expr.vars.append(node.id)
            return

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            dotted = self._dotted(node)
            source = rules.find_source(dotted, self.LANG) if dotted else None
            if source:
                expr.sources.append(source["pattern"])
                return          # `request.args["c"]` is a source, not a read of `request`
            # Not a source: keep walking so `obj[key]` still reads `key`.
            base = node.value
            self._walk_expr(base, expr)
            if isinstance(node, ast.Subscript) and not isinstance(node.slice, ast.Slice):
                self._walk_expr(node.slice, expr)
            return

        if isinstance(node, ast.Call):
            dotted = self._dotted(node.func) or ""
            source = rules.find_source(dotted, self.LANG)
            if source:
                # e.g. request.args.get("cmd") / input()
                expr.sources.append(source["pattern"])
                return

            call = Call(name=dotted, line=getattr(node, "lineno", 0), code=self._segment(node))
            for argument in node.args:
                inner = argument.value if isinstance(argument, ast.Starred) else argument
                call.args.append(self._build_expr(inner))
            for keyword in node.keywords:
                if keyword.arg:
                    call.kwargs[keyword.arg] = self._build_expr(keyword.value)
            expr.calls.append(call)

            # Whatever the arguments read, the surrounding expression reads too.
            for argument_expr in call.args + list(call.kwargs.values()):
                expr.vars.extend(argument_expr.vars)
                expr.sources.extend(argument_expr.sources)
            # A call on something we could not name (a lambda, an element of a
            # list) -- keep walking so we do not lose the variables it reads.
            if not dotted:
                self._walk_expr(node.func, expr)
            return

        if isinstance(node, ast.Constant):
            return

        # Everything else (BinOp, JoinedStr, BoolOp, Compare, List, Dict, ...)
        # is a container: walk the children. This is how taint flows through
        # f-strings and string concatenation.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                self._walk_expr(child, expr)

    # ---------------------------------------------------------------- helpers

    def _dotted(self, node) -> str:
        """Render a dotted name: os.path.join -> 'os.path.join'."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._dotted(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            return self._dotted(node.value)
        if isinstance(node, ast.Call):
            return self._dotted(node.func)
        return ""

    def _target_names(self, node) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [n for e in node.elts for n in self._target_names(e)]
        if isinstance(node, ast.Attribute):
            return [self._dotted(node)]
        if isinstance(node, ast.Subscript):
            return self._target_names(node.value)
        return []

    def _is_always_false(self, node) -> bool:
        """Detect `if False:` and `if 0:` -- dead code a scanner should not report."""
        return isinstance(node, ast.Constant) and node.value in (False, 0, None, "")

    def _segment(self, node) -> str:
        try:
            return ast.get_source_segment(self.source, node) or ""
        except Exception:
            return ""
