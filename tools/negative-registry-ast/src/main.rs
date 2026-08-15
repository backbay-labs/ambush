use quote::ToTokens;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::visit::{self, Visit};
use syn::{
    Attribute, Block, Expr, ExprClosure, Ident, ImplItem, Item, ItemFn, ItemMod, Macro, Meta, Pat,
    Path as SynPath, Result as SynResult, Stmt, Token, Type, braced, parenthesized,
};

const EXPECTED: &str = include_str!("expected-bindings.tsv");
const EXPECTED_SHA256: &str = "0e3b222e79e16a45fe6922f2717a5c14696102f60bc56cb6920aa8ee513d2871";
const SYNC_MACRO: &str = "negative_protocol::assert_registered_negative_case";
const ASYNC_MACRO: &str = "negative_protocol::assert_registered_async_negative_case";
const RESERVED: [&str; 3] = [
    "negative_protocol",
    "assert_registered_negative_case",
    "assert_registered_async_negative_case",
];
const NORMALIZER_HELPERS: [(&str, &str, &str); 2] = [
    (
        "crates/swarm-policy/tests/negative_policy_gates.rs",
        "outcome",
        "026a908baf56b04a1c36ef257755820f0996cfd4c48cfe40d7a93b5f14f5e4e0",
    ),
    (
        "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs",
        "runtime_protocol_outcome",
        "34c3e0f446fc85eaa216f7466c525a042e26dea409cd0fdbbda6a54f16873cc5",
    ),
];

#[derive(Clone, Debug)]
struct ContractRow {
    invariant: String,
    file: PathBuf,
    test_fn: String,
    case_type: String,
    real_adapter: String,
    production_fn: String,
    production_entry: String,
    broken_variant: String,
    macro_path: String,
    edge_validation: String,
    edge_source: PathBuf,
    edge_entry_type: String,
    edge_entry_fn: String,
    edge_guard_type: String,
    edge_guard_fn: String,
}

#[derive(Clone, Debug)]
struct ExpectedRow {
    invariant: String,
    file: String,
    test_fn: String,
    case_type: String,
    real_adapter: String,
    production_fn: String,
    production_entry: String,
    broken_variant: String,
    macro_path: String,
    invocation_digest: String,
    edge_validation: String,
}

#[derive(Debug)]
struct Violation {
    code: &'static str,
    message: String,
}

impl Violation {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn path_string(path: &SynPath) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

fn canonical<T: ToTokens>(value: &T) -> String {
    value.to_token_stream().to_string()
}

fn digest(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn parse_contract(path: &Path) -> Result<Vec<ContractRow>, String> {
    let text = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 15 {
            return Err(format!(
                "{}:{}: expected 15 tab fields",
                path.display(),
                index + 1
            ));
        }
        rows.push(ContractRow {
            invariant: fields[0].to_owned(),
            file: PathBuf::from(fields[1]),
            test_fn: fields[2].to_owned(),
            case_type: fields[3].to_owned(),
            real_adapter: fields[4].to_owned(),
            production_fn: fields[5].to_owned(),
            production_entry: fields[6].to_owned(),
            broken_variant: fields[7].to_owned(),
            macro_path: fields[8].to_owned(),
            edge_validation: fields[9].to_owned(),
            edge_source: PathBuf::from(fields[10]),
            edge_entry_type: fields[11].to_owned(),
            edge_entry_fn: fields[12].to_owned(),
            edge_guard_type: fields[13].to_owned(),
            edge_guard_fn: fields[14].to_owned(),
        });
    }
    Ok(rows)
}

fn parse_expected() -> Result<BTreeMap<String, ExpectedRow>, String> {
    let actual_digest = digest(EXPECTED);
    if actual_digest != EXPECTED_SHA256 {
        return Err(format!(
            "checker baseline digest `{actual_digest}` != pinned `{EXPECTED_SHA256}`"
        ));
    }
    let mut rows = BTreeMap::new();
    for (index, line) in EXPECTED.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        if fields.len() != 11 {
            return Err(format!(
                "expected-bindings.tsv:{}: expected 11 tab fields",
                index + 1
            ));
        }
        let row = ExpectedRow {
            invariant: fields[0].to_owned(),
            file: fields[1].to_owned(),
            test_fn: fields[2].to_owned(),
            case_type: fields[3].to_owned(),
            real_adapter: fields[4].to_owned(),
            production_fn: fields[5].to_owned(),
            production_entry: fields[6].to_owned(),
            broken_variant: fields[7].to_owned(),
            macro_path: fields[8].to_owned(),
            invocation_digest: fields[9].to_owned(),
            edge_validation: fields[10].to_owned(),
        };
        if rows.insert(row.invariant.clone(), row).is_some() {
            return Err(format!(
                "duplicate expected invariant on line {}",
                index + 1
            ));
        }
    }
    Ok(rows)
}

fn attr_path_value(attribute: &Attribute) -> Option<String> {
    let Meta::NameValue(meta) = &attribute.meta else {
        return None;
    };
    if !meta.path.is_ident("path") {
        return None;
    }
    let Expr::Lit(literal) = &meta.value else {
        return None;
    };
    let syn::Lit::Str(value) = &literal.lit else {
        return None;
    };
    Some(value.value())
}

fn canonical_protocol_module(item: &ItemMod) -> bool {
    item.ident == "negative_protocol"
        && item.content.is_none()
        && item.semi.is_some()
        && item.attrs.len() == 1
        && attr_path_value(&item.attrs[0]).as_deref() == Some("../../../tests/negative_protocol.rs")
}

fn item_name(item: &Item) -> Option<&Ident> {
    match item {
        Item::Const(value) => Some(&value.ident),
        Item::Enum(value) => Some(&value.ident),
        Item::Fn(value) => Some(&value.sig.ident),
        Item::Mod(value) => Some(&value.ident),
        Item::Static(value) => Some(&value.ident),
        Item::Struct(value) => Some(&value.ident),
        Item::Trait(value) => Some(&value.ident),
        Item::TraitAlias(value) => Some(&value.ident),
        Item::Type(value) => Some(&value.ident),
        Item::Union(value) => Some(&value.ident),
        _ => None,
    }
}

fn pat_has_reserved(pat: &Pat) -> bool {
    let text = canonical(pat);
    RESERVED.iter().any(|name| {
        text.split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|part| part == *name)
    })
}

#[derive(Default)]
struct ReservedVisitor {
    problems: Vec<String>,
}

impl<'ast> Visit<'ast> for ReservedVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if let Some(name) = item_name(item)
            && RESERVED.contains(&name.to_string().as_str())
            && !matches!(item, Item::Mod(module) if canonical_protocol_module(module))
        {
            self.problems.push(format!("reserved item `{name}`"));
        }
        if let Item::Use(item_use) = item {
            let text = canonical(item_use);
            if RESERVED.iter().any(|name| {
                text.split(|c: char| !c.is_alphanumeric() && c != '_')
                    .any(|part| part == *name)
            }) {
                self.problems
                    .push(format!("reserved import/re-export `{text}`"));
            }
        }
        if let Item::Macro(item_macro) = item
            && item_macro
                .ident
                .as_ref()
                .is_some_and(|ident| RESERVED.contains(&ident.to_string().as_str()))
        {
            self.problems.push(format!(
                "reserved macro definition `{}`",
                item_macro.ident.as_ref().unwrap()
            ));
        }
        visit::visit_item(self, item);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if pat_has_reserved(&local.pat) {
            self.problems.push(format!(
                "reserved local binding `{}`",
                canonical(&local.pat)
            ));
        }
        visit::visit_local(self, local);
    }
}

#[derive(Default)]
struct MacroVisitor {
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for MacroVisitor {
    fn visit_macro(&mut self, mac: &'ast Macro) {
        let path = path_string(&mac.path);
        if path.ends_with("assert_registered_negative_case")
            || path.ends_with("assert_registered_async_negative_case")
        {
            self.paths.push(path);
        }
        visit::visit_macro(self, mac);
    }
}

fn label(input: ParseStream<'_>, expected: &str) -> SynResult<()> {
    let ident: Ident = input.parse()?;
    if ident != expected {
        return Err(syn::Error::new(
            ident.span(),
            format!("expected `{expected}`"),
        ));
    }
    input.parse::<Token![:]>()?;
    Ok(())
}

struct StateField {
    _name: Ident,
    _ty: Type,
    _value: Expr,
}

impl Parse for StateField {
    fn parse(input: ParseStream<'_>) -> SynResult<Self> {
        let name = input.parse()?;
        input.parse::<Token![:]>()?;
        let ty = input.parse()?;
        input.parse::<Token![=]>()?;
        let value = input.parse()?;
        Ok(Self {
            _name: name,
            _ty: ty,
            _value: value,
        })
    }
}

struct ScalarInvocation {
    case: Ident,
    _mutation: Type,
    _control: SynPath,
    _broken: SynPath,
    _state: Vec<StateField>,
    _probe_ty: Type,
    _probe: Expr,
    _outcome: Type,
    real_probe: Ident,
    production: SynPath,
    arguments: Punctuated<Expr, Token![,]>,
    call: Ident,
    normalize: ExprClosure,
    _mirror: ExprClosure,
    _denied: ExprClosure,
    _permitted: ExprClosure,
}

impl Parse for ScalarInvocation {
    fn parse(input: ParseStream<'_>) -> SynResult<Self> {
        label(input, "case")?;
        let case = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "mutation")?;
        let mutation = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "control")?;
        let control = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "broken")?;
        let broken = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "state")?;
        let state_content;
        braced!(state_content in input);
        let state = state_content
            .parse_terminated(StateField::parse, Token![,])?
            .into_iter()
            .collect();
        input.parse::<Token![,]>()?;
        label(input, "probe")?;
        let probe_ty = input.parse()?;
        input.parse::<Token![=]>()?;
        let probe = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "outcome")?;
        let outcome = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "real_probe")?;
        let real_probe = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "production")?;
        let production = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "arguments")?;
        let arguments_content;
        parenthesized!(arguments_content in input);
        let arguments = arguments_content.parse_terminated(Expr::parse, Token![,])?;
        input.parse::<Token![,]>()?;
        label(input, "call")?;
        let call = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "normalize")?;
        let normalize = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "mirror")?;
        let mirror = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "denied")?;
        let denied = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "permitted")?;
        let permitted = input.parse()?;
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("unexpected trailing protocol tokens"));
        }
        Ok(Self {
            case,
            _mutation: mutation,
            _control: control,
            _broken: broken,
            _state: state,
            _probe_ty: probe_ty,
            _probe: probe,
            _outcome: outcome,
            real_probe,
            production,
            arguments,
            call,
            normalize,
            _mirror: mirror,
            _denied: denied,
            _permitted: permitted,
        })
    }
}

struct BatchInvocation {
    case: Ident,
    _mutation: Type,
    _control: SynPath,
    _broken: SynPath,
    _state: Vec<StateField>,
    _probe_ty: Type,
    _probe: Expr,
    _outcome: Type,
    real_probe: Ident,
    production: SynPath,
    arguments: Punctuated<Expr, Token![,]>,
    item: Ident,
    iterator: Expr,
    normalize: ExprClosure,
    _mirror: ExprClosure,
    _denied: ExprClosure,
    _permitted: ExprClosure,
}

impl Parse for BatchInvocation {
    fn parse(input: ParseStream<'_>) -> SynResult<Self> {
        label(input, "case")?;
        let case = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "mutation")?;
        let mutation = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "control")?;
        let control = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "broken")?;
        let broken = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "state")?;
        let state_content;
        braced!(state_content in input);
        let state = state_content
            .parse_terminated(StateField::parse, Token![,])?
            .into_iter()
            .collect();
        input.parse::<Token![,]>()?;
        label(input, "probe")?;
        let probe_ty = input.parse()?;
        input.parse::<Token![=]>()?;
        let probe = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "outcome")?;
        let outcome = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "real_probe")?;
        let real_probe = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "production_each")?;
        let production = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "arguments_each")?;
        let arguments_content;
        parenthesized!(arguments_content in input);
        let arguments = arguments_content.parse_terminated(Expr::parse, Token![,])?;
        input.parse::<Token![,]>()?;
        label(input, "items")?;
        let item = input.parse()?;
        input.parse::<Token![in]>()?;
        let iterator = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "normalize_each")?;
        let normalize = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "mirror")?;
        let mirror = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "denied")?;
        let denied = input.parse()?;
        input.parse::<Token![,]>()?;
        label(input, "permitted")?;
        let permitted = input.parse()?;
        if input.peek(Token![,]) {
            input.parse::<Token![,]>()?;
        }
        if !input.is_empty() {
            return Err(input.error("unexpected trailing protocol tokens"));
        }
        Ok(Self {
            case,
            _mutation: mutation,
            _control: control,
            _broken: broken,
            _state: state,
            _probe_ty: probe_ty,
            _probe: probe,
            _outcome: outcome,
            real_probe,
            production,
            arguments,
            item,
            iterator,
            normalize,
            _mirror: mirror,
            _denied: denied,
            _permitted: permitted,
        })
    }
}

struct ParsedInvocation {
    case: String,
    mutation: String,
    control: String,
    broken: String,
    production: String,
    digest: String,
}

fn one_closure_input(closure: &ExprClosure, expected: &str) -> bool {
    struct IdentUse<'a> {
        expected: &'a str,
        uses: usize,
    }
    impl<'ast> Visit<'ast> for IdentUse<'_> {
        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.path.is_ident(self.expected) {
                self.uses += 1;
            }
            visit::visit_expr_path(self, expression);
        }
    }
    let binding_matches = closure.inputs.len() == 1
        && matches!(closure.inputs.first(), Some(Pat::Ident(value)) if value.ident == expected);
    let mut visitor = IdentUse { expected, uses: 0 };
    visitor.visit_expr(&closure.body);
    binding_matches && visitor.uses > 0
}

fn two_closure_inputs(closure: &ExprClosure, first: &str, second: &str) -> bool {
    closure.inputs.len() == 2
        && matches!(closure.inputs.first(), Some(Pat::Ident(value)) if value.ident == first)
        && matches!(closure.inputs.iter().nth(1), Some(Pat::Ident(value)) if value.ident == second)
        && {
            struct Uses<'a> {
                names: [&'a str; 2],
                seen: [bool; 2],
            }
            impl<'ast> Visit<'ast> for Uses<'_> {
                fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
                    for (index, name) in self.names.iter().enumerate() {
                        if expression.path.is_ident(name) {
                            self.seen[index] = true;
                        }
                    }
                    visit::visit_expr_path(self, expression);
                }
            }
            let mut visitor = Uses {
                names: [first, second],
                seen: [false, false],
            };
            visitor.visit_expr(&closure.body);
            visitor.seen == [true, true]
        }
}

fn parse_invocation(mac: &Macro, expected_macro: &str) -> Result<ParsedInvocation, String> {
    if expected_macro == SYNC_MACRO && canonical(&mac.tokens).contains("production_each") {
        let value: BatchInvocation =
            syn::parse2(mac.tokens.clone()).map_err(|error| error.to_string())?;
        if value.real_probe != "probe"
            || value.item != "item"
            || !two_closure_inputs(&value.normalize, "production_result", "item")
        {
            return Err("batch probe/item/normalizer bindings drifted".to_owned());
        }
        let iterator = canonical(&value.iterator);
        if iterator != "probe . iter ()" {
            return Err(format!(
                "batch iterator `{iterator}` is not exact probe.iter()"
            ));
        }
        let production = path_string(&value.production);
        let material = format!(
            "batch|{production}|{}|{}|{}",
            canonical(&value.arguments),
            iterator,
            canonical(&value.normalize)
        );
        Ok(ParsedInvocation {
            case: value.case.to_string(),
            mutation: canonical(&value._mutation),
            control: path_string(&value._control),
            broken: path_string(&value._broken),
            production,
            digest: digest(&material),
        })
    } else {
        let value: ScalarInvocation =
            syn::parse2(mac.tokens.clone()).map_err(|error| error.to_string())?;
        if value.real_probe != "probe" || !one_closure_input(&value.normalize, "production_result")
        {
            return Err("probe/normalizer binding drifted".to_owned());
        }
        let call = value.call.to_string();
        let expected_call = if expected_macro == ASYNC_MACRO {
            "awaited"
        } else {
            "sync"
        };
        if call != expected_call {
            return Err(format!("call kind `{call}` != `{expected_call}`"));
        }
        let production = path_string(&value.production);
        let material = format!(
            "scalar|{production}|{call}|{}|{}",
            canonical(&value.arguments),
            canonical(&value.normalize)
        );
        Ok(ParsedInvocation {
            case: value.case.to_string(),
            mutation: canonical(&value._mutation),
            control: path_string(&value._control),
            broken: path_string(&value._broken),
            production,
            digest: digest(&material),
        })
    }
}

fn direct_test_macro<'a>(
    function: &'a ItemFn,
    expected_path: &str,
) -> Result<&'a Macro, Violation> {
    let mut visitor = MacroVisitor::default();
    visitor.visit_block(&function.block);
    if visitor.paths != [expected_path] {
        return Err(Violation::new(
            "ast-macro-path",
            format!(
                "{} macro inventory {:?}, expected [{}]",
                function.sig.ident, visitor.paths, expected_path
            ),
        ));
    }
    let direct = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Macro(value) if path_string(&value.mac.path) == expected_path => Some(&value.mac),
            _ => None,
        })
        .collect::<Vec<_>>();
    if direct.len() != 1 {
        return Err(Violation::new(
            "ast-macro-placement",
            format!(
                "{} canonical macro is not one direct top-level statement",
                function.sig.ident
            ),
        ));
    }
    let macro_index = function
        .block
        .stmts
        .iter()
        .position(|statement| {
            matches!(statement, Stmt::Macro(value) if path_string(&value.mac.path) == expected_path)
        })
        .expect("the direct macro inventory was checked above");
    if function.block.stmts[..macro_index]
        .iter()
        .any(statement_unconditionally_exits)
    {
        return Err(Violation::new(
            "ast-macro-placement",
            format!(
                "{} canonical macro follows an unconditional exit",
                function.sig.ident
            ),
        ));
    }
    Ok(direct[0])
}

fn statement_unconditionally_exits(statement: &Stmt) -> bool {
    match statement {
        Stmt::Expr(Expr::Return(_), _) => true,
        Stmt::Expr(Expr::Macro(value), _) => {
            value.mac.path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "panic" | "todo" | "unreachable"
                )
            })
        }
        Stmt::Macro(value) => value.mac.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "panic" | "todo" | "unreachable"
            )
        }),
        _ => false,
    }
}

fn collect_functions<'a>(items: &'a [Item], functions: &mut Vec<(String, String, &'a Block)>) {
    for item in items {
        match item {
            Item::Fn(function) => functions.push((
                "-".to_owned(),
                function.sig.ident.to_string(),
                &function.block,
            )),
            Item::Impl(implementation) => {
                let type_name = match implementation.self_ty.as_ref() {
                    Type::Path(path) => path
                        .path
                        .segments
                        .last()
                        .map(|segment| segment.ident.to_string())
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                for member in &implementation.items {
                    if let ImplItem::Fn(function) = member {
                        functions.push((
                            type_name.clone(),
                            function.sig.ident.to_string(),
                            &function.block,
                        ));
                    }
                }
            }
            Item::Mod(module) => {
                if let Some((_, nested)) = &module.content {
                    collect_functions(nested, functions);
                }
            }
            _ => {}
        }
    }
}

struct GuardCallVisitor<'a> {
    guard_type: &'a str,
    guard_fn: &'a str,
    inactive: usize,
    calls: usize,
}

impl<'ast> Visit<'ast> for GuardCallVisitor<'_> {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if self.inactive == 0
            && let Expr::Path(path) = expression.func.as_ref()
            && path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == self.guard_fn)
        {
            let identity = path_string(&path.path);
            if self.guard_type == "-"
                || identity
                    .split("::")
                    .any(|segment| segment == self.guard_type || segment == "Self")
                || path.path.segments.len() == 1
            {
                self.calls += 1;
            }
        }
        visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        if self.inactive == 0 && expression.method == self.guard_fn {
            self.calls += 1;
        }
        visit::visit_expr_method_call(self, expression);
    }

    fn visit_expr_closure(&mut self, expression: &'ast ExprClosure) {
        self.inactive += 1;
        visit::visit_expr_closure(self, expression);
        self.inactive -= 1;
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.inactive += 1;
        visit::visit_expr_async(self, expression);
        self.inactive -= 1;
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        if matches!(expression.cond.as_ref(), Expr::Lit(value) if matches!(value.lit, syn::Lit::Bool(ref flag) if !flag.value))
        {
            self.visit_expr(expression.cond.as_ref());
            self.inactive += 1;
            self.visit_block(&expression.then_branch);
            self.inactive -= 1;
            if let Some((_, branch)) = &expression.else_branch {
                self.visit_expr(branch);
            }
        } else {
            visit::visit_expr_if(self, expression);
        }
    }
}

fn validate_mechanical_edge(row: &ContractRow) -> Option<Violation> {
    if row.edge_validation != "mechanical" {
        return None;
    }
    let source = match fs::read_to_string(&row.edge_source) {
        Ok(value) => value,
        Err(error) => {
            return Some(Violation::new(
                "ast-edge-source",
                format!("{}: {error}", row.edge_source.display()),
            ));
        }
    };
    let file = match syn::parse_file(&source) {
        Ok(value) => value,
        Err(error) => {
            return Some(Violation::new(
                "ast-edge-source",
                format!("{}: {error}", row.edge_source.display()),
            ));
        }
    };
    let mut functions = Vec::new();
    collect_functions(&file.items, &mut functions);
    let candidates = functions
        .into_iter()
        .filter(|(type_name, function, _)| {
            type_name == &row.edge_entry_type && function == &row.edge_entry_fn
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return Some(Violation::new(
            "ast-edge-entry",
            format!(
                "{} has {} `{}`::`{}` entry bodies",
                row.invariant,
                candidates.len(),
                row.edge_entry_type,
                row.edge_entry_fn
            ),
        ));
    }
    let mut visitor = GuardCallVisitor {
        guard_type: &row.edge_guard_type,
        guard_fn: &row.edge_guard_fn,
        inactive: 0,
        calls: 0,
    };
    visitor.visit_block(candidates[0].2);
    if visitor.calls == 0 {
        return Some(Violation::new(
            "ast-edge-missing",
            format!(
                "{} entry `{}`::`{}` has no live AST call edge to `{}`::`{}`",
                row.invariant,
                row.edge_entry_type,
                row.edge_entry_fn,
                row.edge_guard_type,
                row.edge_guard_fn
            ),
        ));
    }
    None
}

fn validate_normalizer_helpers() -> Vec<Violation> {
    let mut violations = Vec::new();
    for (path, function_name, expected_digest) in NORMALIZER_HELPERS {
        let source = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) => {
                violations.push(Violation::new(
                    "ast-normalizer-helper",
                    format!("{path}: {error}"),
                ));
                continue;
            }
        };
        let file = match syn::parse_file(&source) {
            Ok(value) => value,
            Err(error) => {
                violations.push(Violation::new(
                    "ast-normalizer-helper",
                    format!("{path}: {error}"),
                ));
                continue;
            }
        };
        let candidates = file
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Fn(function) if function.sig.ident == function_name => Some(function),
                _ => None,
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            violations.push(Violation::new(
                "ast-normalizer-helper",
                format!(
                    "{path} has {} `{function_name}` functions",
                    candidates.len()
                ),
            ));
            continue;
        }
        let actual = digest(&canonical(&candidates[0].block));
        if actual != expected_digest {
            violations.push(Violation::new(
                "ast-normalizer-helper",
                format!("{path} `{function_name}` digest `{actual}` != pinned `{expected_digest}`"),
            ));
        }
    }
    violations
}

fn validate_row(
    row: &ContractRow,
    strict: bool,
    expected: &BTreeMap<String, ExpectedRow>,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let source = match fs::read_to_string(&row.file) {
        Ok(value) => value,
        Err(error) => {
            return vec![Violation::new(
                "ast-source-read",
                format!("{}: {error}", row.file.display()),
            )];
        }
    };
    let file = match syn::parse_file(&source) {
        Ok(value) => value,
        Err(error) => {
            return vec![Violation::new(
                "ast-source-parse",
                format!("{}: {error}", row.file.display()),
            )];
        }
    };
    let modules = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Mod(value) if value.ident == "negative_protocol" => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    if modules.len() != 1 || !canonical_protocol_module(modules[0]) {
        violations.push(Violation::new(
            "ast-protocol-module",
            format!(
                "{} lacks the exact canonical protocol module",
                row.file.display()
            ),
        ));
    }
    let mut reserved = ReservedVisitor::default();
    reserved.visit_file(&file);
    for problem in reserved.problems {
        violations.push(Violation::new(
            "ast-reserved-binding",
            format!("{}: {problem}", row.file.display()),
        ));
    }
    let tests = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Fn(value) if value.sig.ident == row.test_fn => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    if tests.len() != 1 {
        violations.push(Violation::new(
            "ast-test-identity",
            format!(
                "{} has {} top-level `{}` functions",
                row.file.display(),
                tests.len(),
                row.test_fn
            ),
        ));
        return violations;
    }
    let mac = match direct_test_macro(tests[0], &row.macro_path) {
        Ok(value) => value,
        Err(error) => {
            violations.push(error);
            return violations;
        }
    };
    let parsed = match parse_invocation(mac, &row.macro_path) {
        Ok(value) => value,
        Err(error) => {
            violations.push(Violation::new(
                "ast-invocation-parse",
                format!("{}: {error}", row.invariant),
            ));
            return violations;
        }
    };
    let mutation = row.broken_variant.split("::").next().unwrap_or_default();
    let control = format!("{mutation}::None");
    if parsed.case != row.case_type
        || parsed.production != row.production_entry
        || parsed.mutation != mutation
        || parsed.control != control
        || parsed.broken != row.broken_variant
    {
        violations.push(Violation::new(
            "ast-source-binding",
            format!(
                "{} source case/mutation/control/broken/production drifted",
                row.invariant
            ),
        ));
    }
    if strict {
        match expected.get(&row.invariant) {
            None => violations.push(Violation::new(
                "ast-expected-missing",
                format!("{} absent from checker baseline", row.invariant),
            )),
            Some(value) => {
                let actual = [
                    row.file.to_string_lossy().to_string(),
                    row.test_fn.clone(),
                    row.case_type.clone(),
                    row.real_adapter.clone(),
                    row.production_fn.clone(),
                    row.production_entry.clone(),
                    row.broken_variant.clone(),
                    row.macro_path.clone(),
                    parsed.digest.clone(),
                    row.edge_validation.clone(),
                ];
                let wanted = [
                    value.file.clone(),
                    value.test_fn.clone(),
                    value.case_type.clone(),
                    value.real_adapter.clone(),
                    value.production_fn.clone(),
                    value.production_entry.clone(),
                    value.broken_variant.clone(),
                    value.macro_path.clone(),
                    value.invocation_digest.clone(),
                    value.edge_validation.clone(),
                ];
                if actual != wanted {
                    violations.push(Violation::new(
                        "ast-expected-binding-drift",
                        format!(
                            "{} actual {:?} != checker baseline {:?}",
                            row.invariant, actual, wanted
                        ),
                    ));
                }
            }
        }
    }
    if let Some(edge) = validate_mechanical_edge(row) {
        violations.push(edge);
    }
    violations
}

fn emitted_row(row: &ContractRow) -> Result<String, String> {
    let source = fs::read_to_string(&row.file).map_err(|error| error.to_string())?;
    let file = syn::parse_file(&source).map_err(|error| error.to_string())?;
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(value) if value.sig.ident == row.test_fn => Some(value),
            _ => None,
        })
        .ok_or_else(|| "test missing".to_owned())?;
    let mac = direct_test_macro(function, &row.macro_path).map_err(|error| error.message)?;
    let parsed = parse_invocation(mac, &row.macro_path)?;
    Ok([
        row.invariant.clone(),
        row.file.to_string_lossy().to_string(),
        row.test_fn.clone(),
        row.case_type.clone(),
        row.real_adapter.clone(),
        row.production_fn.clone(),
        row.production_entry.clone(),
        row.broken_variant.clone(),
        row.macro_path.clone(),
        parsed.digest,
        row.edge_validation.clone(),
    ]
    .join("\t"))
}

fn main() {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if arguments.len() != 2 || !matches!(arguments[0].as_str(), "--check" | "--fixture" | "--emit")
    {
        eprintln!("usage: negative-registry-ast (--check|--fixture|--emit) CONTRACT.tsv");
        std::process::exit(2);
    }
    let rows = match parse_contract(Path::new(&arguments[1])) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("[ast-contract-read] {error}");
            std::process::exit(1);
        }
    };
    if arguments[0] == "--emit" {
        for row in &rows {
            match emitted_row(row) {
                Ok(value) => println!("{value}"),
                Err(error) => {
                    eprintln!("[ast-emit] {}: {error}", row.invariant);
                    std::process::exit(1);
                }
            }
        }
        return;
    }
    let expected = match parse_expected() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("[ast-expected-parse] {error}");
            std::process::exit(1);
        }
    };
    let strict = arguments[0] == "--check";
    let mut violations = Vec::new();
    if strict {
        let actual = rows
            .iter()
            .map(|row| row.invariant.clone())
            .collect::<BTreeSet<_>>();
        let wanted = expected.keys().cloned().collect::<BTreeSet<_>>();
        if actual != wanted {
            violations.push(Violation::new(
                "ast-expected-set-drift",
                format!("actual {:?} != checker baseline {:?}", actual, wanted),
            ));
        }
        violations.extend(validate_normalizer_helpers());
    }
    for row in &rows {
        violations.extend(validate_row(row, strict, &expected));
    }
    if violations.is_empty() {
        println!("negative-registry-ast OK: {} source contracts", rows.len());
        return;
    }
    for violation in violations {
        eprintln!("[{}] {}", violation.code, violation.message);
    }
    std::process::exit(1);
}
