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
    Attribute, Expr, ExprClosure, Ident, Item, ItemExternCrate, ItemFn, ItemMod, Macro, Meta, Pat,
    Path as SynPath, Result as SynResult, Stmt, Token, Type, Visibility, braced, parenthesized,
};

const EXPECTED: &str = include_str!("expected-bindings.tsv");
const EXPECTED_SHA256: &str = "996df668004609a39b0abb744997c613c437483370aadc0e9911340a01665e67";
const PROTOCOL_SOURCE: &str = "tests/negative_protocol.rs";
const PROTOCOL_SEMANTIC_SHA256: &str =
    "2913a5d3a7dc9020b5526f1b98120c7b5e474c2a6ba2d3c1a2d7a4828af0a121";
const SYNC_MACRO: &str = "negative_protocol::assert_registered_negative_case";
const RESERVED: [&str; 2] = ["negative_protocol", "assert_registered_negative_case"];
const CRATE_BINDINGS: [(&str, &str); 5] = [
    ("swarm_policy", "__phase285_swarm_policy"),
    ("swarm_response", "__phase285_swarm_response"),
    ("swarm_runtime", "__phase285_swarm_runtime"),
    ("swarm_spine", "__phase285_swarm_spine"),
    ("serde_json", "__phase285_serde_json"),
];
const POLICY_BINDINGS: [(&str, &str); 1] = [CRATE_BINDINGS[0]];
const RESPONSE_BINDINGS: [(&str, &str); 2] = [CRATE_BINDINGS[1], CRATE_BINDINGS[4]];
const RUNTIME_BINDINGS: [(&str, &str); 1] = [CRATE_BINDINGS[2]];
const SPINE_BINDINGS: [(&str, &str); 1] = [CRATE_BINDINGS[3]];
const REGISTERED_SOURCE_SEMANTIC_SHA256: [(&str, &str); 4] = [
    (
        "crates/swarm-policy/tests/negative_policy_gates.rs",
        "9ddedd8e2c46ae05c2a92609650dc2d571b5bc88806f09c8e6a1d0a844aace01",
    ),
    (
        "crates/swarm-response/tests/negative_containment_and_rollback.rs",
        "31082b7801c5d5caed53294a5c6a396ea3270a4e3ea6cc7a1308ab66c133ddb4",
    ),
    (
        "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs",
        "d2c74d06fa733806330980efc95f08734562a20009197de1fa1dfe3f69ab822e",
    ),
    (
        "crates/swarm-spine/tests/negative_envelope_and_chain.rs",
        "4aab18e0f432b0360964e7ed39ca6a9a7243b9c8e1520b35884d096811ae53e7",
    ),
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
        "85d60edcf0d4a394a2b0b7c72eb38365fe0a40721a5657cbb897a643e8070a5e",
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
    semantic_digest: String,
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
        if fields.len() != 10 {
            return Err(format!(
                "{}:{}: expected 10 tab fields",
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
            semantic_digest: fields[9].to_owned(),
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

fn expected_crate_bindings(path: &Path) -> Option<&'static [(&'static str, &'static str)]> {
    match path.to_string_lossy().as_ref() {
        "crates/swarm-policy/tests/negative_policy_gates.rs" => Some(&POLICY_BINDINGS),
        "crates/swarm-response/tests/negative_containment_and_rollback.rs" => {
            Some(&RESPONSE_BINDINGS)
        }
        "crates/swarm-runtime/tests/negative_runtime_fail_closed.rs" => Some(&RUNTIME_BINDINGS),
        "crates/swarm-spine/tests/negative_envelope_and_chain.rs" => Some(&SPINE_BINDINGS),
        _ => None,
    }
}

fn is_reserved_binding(name: &str) -> bool {
    RESERVED.contains(&name)
        || CRATE_BINDINGS
            .iter()
            .any(|(root, alias)| name == *root || name == *alias)
}

fn source_production_path(production_entry: &str) -> Option<String> {
    let (root, suffix) = production_entry.split_once("::")?;
    let alias = CRATE_BINDINGS
        .iter()
        .find_map(|(candidate, alias)| (*candidate == root).then_some(*alias))?;
    Some(format!("crate::{alias}::{suffix}"))
}

fn exact_extern_crate(item: &ItemExternCrate, root: &str, alias: &str) -> bool {
    item.attrs.is_empty()
        && matches!(item.vis, Visibility::Inherited)
        && item.ident == root
        && item
            .rename
            .as_ref()
            .is_some_and(|(_, actual)| actual == alias)
}

#[derive(Default)]
struct ExternCrateVisitor<'ast> {
    declarations: Vec<&'ast ItemExternCrate>,
}

impl<'ast> Visit<'ast> for ExternCrateVisitor<'ast> {
    fn visit_item_extern_crate(&mut self, item: &'ast ItemExternCrate) {
        self.declarations.push(item);
        visit::visit_item_extern_crate(self, item);
    }
}

fn validate_crate_bindings(file: &syn::File, path: &Path, strict: bool) -> Vec<Violation> {
    let Some(expected) = expected_crate_bindings(path) else {
        return if strict {
            vec![Violation::new(
                "ast-crate-binding",
                format!("{} is not a pinned negative-test target", path.display()),
            )]
        } else {
            Vec::new()
        };
    };
    let top_level = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::ExternCrate(value) => Some(value),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut visitor = ExternCrateVisitor::default();
    visitor.visit_file(file);
    let exact = |item: &&ItemExternCrate| {
        expected
            .iter()
            .any(|(root, alias)| exact_extern_crate(item, root, alias))
    };
    if top_level.len() == expected.len()
        && visitor.declarations.len() == expected.len()
        && top_level.iter().all(exact)
        && visitor.declarations.iter().all(exact)
        && expected.iter().all(|(root, alias)| {
            top_level
                .iter()
                .filter(|item| exact_extern_crate(item, root, alias))
                .count()
                == 1
        })
    {
        Vec::new()
    } else {
        vec![Violation::new(
            "ast-crate-binding",
            format!(
                "{} extern-crate inventory is not the exact pinned top-level set {:?}",
                path.display(),
                expected
            ),
        )]
    }
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
    RESERVED
        .iter()
        .copied()
        .chain(
            CRATE_BINDINGS
                .iter()
                .flat_map(|(root, alias)| [*root, *alias]),
        )
        .any(|name| {
            text.split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|part| part == name)
        })
}

#[derive(Default)]
struct ReservedVisitor {
    problems: Vec<String>,
}

impl<'ast> Visit<'ast> for ReservedVisitor {
    fn visit_item(&mut self, item: &'ast Item) {
        if let Some(name) = item_name(item)
            && is_reserved_binding(&name.to_string())
            && !matches!(item, Item::Mod(module) if canonical_protocol_module(module))
        {
            self.problems.push(format!("reserved item `{name}`"));
        }
        if let Item::Use(item_use) = item {
            let text = canonical(item_use);
            if RESERVED
                .iter()
                .copied()
                .chain(CRATE_BINDINGS.iter().map(|(_, alias)| *alias))
                .any(|name| {
                    text.split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|part| part == name)
                })
            {
                self.problems
                    .push(format!("reserved import/re-export `{text}`"));
            }
        }
        if let Item::Macro(item_macro) = item
            && item_macro
                .ident
                .as_ref()
                .is_some_and(|ident| is_reserved_binding(&ident.to_string()))
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
        if path.ends_with("assert_registered_negative_case") {
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
    _arguments: Punctuated<Expr, Token![,]>,
    call: Ident,
    normalize: ExprClosure,
    mirror: ExprClosure,
    denied: ExprClosure,
    permitted: ExprClosure,
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
            _arguments: arguments,
            call,
            normalize,
            mirror,
            denied,
            permitted,
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
    _arguments: Punctuated<Expr, Token![,]>,
    item: Ident,
    iterator: Expr,
    normalize: ExprClosure,
    mirror: ExprClosure,
    denied: ExprClosure,
    permitted: ExprClosure,
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
            _arguments: arguments,
            item,
            iterator,
            normalize,
            mirror,
            denied,
            permitted,
        })
    }
}

struct ParsedInvocation {
    case: String,
    mutation: String,
    control: String,
    broken: String,
    production: String,
}

fn closure_identifiers(closure: &ExprClosure) -> Option<Vec<String>> {
    closure
        .inputs
        .iter()
        .map(|input| match input {
            Pat::Ident(value) => Some(value.ident.to_string()),
            _ => None,
        })
        .collect()
}

fn expression_uses_identifier(expression: &Expr, expected: &str) -> bool {
    fn tokens_use_identifier(tokens: &proc_macro2::TokenStream, expected: &str) -> bool {
        tokens.clone().into_iter().any(|token| match token {
            proc_macro2::TokenTree::Ident(value) => value == expected,
            proc_macro2::TokenTree::Group(value) => {
                tokens_use_identifier(&value.stream(), expected)
            }
            _ => false,
        })
    }

    struct IdentUse<'a> {
        expected: &'a str,
        used: bool,
    }
    impl<'ast> Visit<'ast> for IdentUse<'_> {
        fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
            if expression.path.is_ident(self.expected) {
                self.used = true;
            }
            visit::visit_expr_path(self, expression);
        }

        fn visit_macro(&mut self, value: &'ast Macro) {
            if tokens_use_identifier(&value.tokens, self.expected) {
                self.used = true;
            }
            visit::visit_macro(self, value);
        }
    }
    let mut visitor = IdentUse {
        expected,
        used: false,
    };
    visitor.visit_expr(expression);
    visitor.used
}

fn mirror_bindings_are_live(closure: &ExprClosure) -> bool {
    let Some(inputs) = closure_identifiers(closure) else {
        return false;
    };
    if inputs.len() != 3 {
        return false;
    }
    inputs.iter().enumerate().all(|(index, input)| {
        if index == 2 && input.starts_with('_') {
            return false;
        }
        input.starts_with('_') || expression_uses_identifier(&closure.body, input)
    })
}

fn predicate_binding_is_live(closure: &ExprClosure) -> bool {
    let Some(inputs) = closure_identifiers(closure) else {
        return false;
    };
    inputs.len() == 1
        && !inputs[0].starts_with('_')
        && expression_uses_identifier(&closure.body, &inputs[0])
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
        let mirror_live = mirror_bindings_are_live(&value.mirror);
        let denied_live = predicate_binding_is_live(&value.denied);
        let permitted_live = predicate_binding_is_live(&value.permitted);
        if !mirror_live || !denied_live || !permitted_live {
            return Err(format!(
                "batch semantic bindings are not live (mirror={mirror_live}, denied={denied_live}, permitted={permitted_live})"
            ));
        }
        let production = path_string(&value.production);
        Ok(ParsedInvocation {
            case: value.case.to_string(),
            mutation: canonical(&value._mutation),
            control: path_string(&value._control),
            broken: path_string(&value._broken),
            production,
        })
    } else {
        let value: ScalarInvocation =
            syn::parse2(mac.tokens.clone()).map_err(|error| error.to_string())?;
        if value.real_probe != "probe" || !one_closure_input(&value.normalize, "production_result")
        {
            return Err("probe/normalizer binding drifted".to_owned());
        }
        let call = value.call.to_string();
        if !matches!(call.as_str(), "sync" | "awaited") {
            return Err(format!(
                "call kind `{call}` is neither `sync` nor `awaited`"
            ));
        }
        let mirror_live = mirror_bindings_are_live(&value.mirror);
        let denied_live = predicate_binding_is_live(&value.denied);
        let permitted_live = predicate_binding_is_live(&value.permitted);
        if !mirror_live || !denied_live || !permitted_live {
            return Err(format!(
                "semantic bindings are not live (mirror={mirror_live}, denied={denied_live}, permitted={permitted_live})"
            ));
        }
        let production = path_string(&value.production);
        Ok(ParsedInvocation {
            case: value.case.to_string(),
            mutation: canonical(&value._mutation),
            control: path_string(&value._control),
            broken: path_string(&value._broken),
            production,
        })
    }
}

fn direct_test_macro<'a>(
    function: &'a ItemFn,
    expected_path: &str,
) -> Result<&'a Macro, Violation> {
    let exact_builtin_test = function.attrs.len() == 1 && function.attrs[0].path().is_ident("test");
    if !exact_builtin_test
        || function.sig.asyncness.is_some()
        || !function.sig.inputs.is_empty()
        || !matches!(function.sig.output, syn::ReturnType::Default)
    {
        return Err(Violation::new(
            "ast-macro-placement",
            format!(
                "{} must be one ordinary #[test] function with no async/proc-macro attribute, parameters, or return type",
                function.sig.ident
            ),
        ));
    }
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
    let mut exits = EarlyExitVisitor::default();
    for statement in &function.block.stmts[..macro_index] {
        exits.visit_stmt(statement);
    }
    if exits.found {
        return Err(Violation::new(
            "ast-macro-placement",
            format!(
                "{} setup can return before the canonical macro",
                function.sig.ident
            ),
        ));
    }
    Ok(direct[0])
}

#[derive(Default)]
struct EarlyExitVisitor {
    found: bool,
}

impl<'ast> Visit<'ast> for EarlyExitVisitor {
    fn visit_expr_return(&mut self, _expression: &'ast syn::ExprReturn) {
        self.found = true;
    }

    fn visit_expr_try(&mut self, _expression: &'ast syn::ExprTry) {
        self.found = true;
    }

    fn visit_macro(&mut self, value: &'ast Macro) {
        if value.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "panic" | "todo" | "unreachable"
            )
        }) {
            self.found = true;
            return;
        }
        visit::visit_macro(self, value);
    }

    fn visit_expr_closure(&mut self, _expression: &'ast ExprClosure) {
        // A return inside a closure exits that closure, not the registered test.
    }

    fn visit_expr_async(&mut self, _expression: &'ast syn::ExprAsync) {
        // A return inside an async block exits its future, not the test function.
    }
}

fn validate_normalizer_helpers(sources: &BTreeMap<PathBuf, syn::File>) -> Vec<Violation> {
    let mut violations = Vec::new();
    for (path, function_name, expected_digest) in NORMALIZER_HELPERS {
        let Some(file) = sources.get(Path::new(path)) else {
            violations.push(Violation::new(
                "ast-normalizer-helper",
                format!("{path}: parsed source is unavailable"),
            ));
            continue;
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

fn validate_protocol_semantics() -> Option<Violation> {
    let source = match fs::read_to_string(PROTOCOL_SOURCE) {
        Ok(value) => value,
        Err(error) => {
            return Some(Violation::new(
                "ast-protocol-semantic-drift",
                format!("{PROTOCOL_SOURCE}: {error}"),
            ));
        }
    };
    let file = match syn::parse_file(&source) {
        Ok(value) => value,
        Err(error) => {
            return Some(Violation::new(
                "ast-protocol-semantic-drift",
                format!("{PROTOCOL_SOURCE}: {error}"),
            ));
        }
    };
    let actual = digest(&canonical(&file));
    if actual == PROTOCOL_SEMANTIC_SHA256 {
        None
    } else {
        Some(Violation::new(
            "ast-protocol-semantic-drift",
            format!(
                "{PROTOCOL_SOURCE} semantic digest `{actual}` != pinned `{PROTOCOL_SEMANTIC_SHA256}`"
            ),
        ))
    }
}

fn parse_registered_sources(
    rows: &[ContractRow],
) -> (BTreeMap<PathBuf, syn::File>, Vec<Violation>) {
    let mut sources = BTreeMap::new();
    let mut violations = Vec::new();
    for path in rows
        .iter()
        .map(|row| row.file.clone())
        .collect::<BTreeSet<_>>()
    {
        let source = match fs::read_to_string(&path) {
            Ok(value) => value,
            Err(error) => {
                violations.push(Violation::new(
                    "ast-source-read",
                    format!("{}: {error}", path.display()),
                ));
                continue;
            }
        };
        match syn::parse_file(&source) {
            Ok(file) => {
                sources.insert(path, file);
            }
            Err(error) => violations.push(Violation::new(
                "ast-source-parse",
                format!("{}: {error}", path.display()),
            )),
        }
    }
    (sources, violations)
}

fn validate_registered_source_semantics(
    rows: &[ContractRow],
    sources: &BTreeMap<PathBuf, syn::File>,
) -> Vec<Violation> {
    let actual_paths = rows
        .iter()
        .map(|row| row.file.to_string_lossy().to_string())
        .collect::<BTreeSet<_>>();
    let expected_paths = REGISTERED_SOURCE_SEMANTIC_SHA256
        .iter()
        .map(|(path, _)| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    let mut violations = Vec::new();
    if actual_paths != expected_paths {
        violations.push(Violation::new(
            "ast-source-file-set-drift",
            format!("registered source files {actual_paths:?} != pinned {expected_paths:?}"),
        ));
    }
    for (path, expected_digest) in REGISTERED_SOURCE_SEMANTIC_SHA256 {
        let Some(file) = sources.get(Path::new(path)) else {
            continue;
        };
        let actual = digest(&canonical(&file));
        if actual != expected_digest {
            violations.push(Violation::new(
                "ast-source-semantic-drift",
                format!("{path} semantic digest `{actual}` != pinned `{expected_digest}`"),
            ));
        }
    }
    violations
}

fn validate_source_file(path: &Path, file: &syn::File, strict: bool) -> Vec<Violation> {
    let mut violations = validate_crate_bindings(file, path, strict);
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
                path.display()
            ),
        ));
    }
    let mut reserved = ReservedVisitor::default();
    reserved.visit_file(file);
    for problem in reserved.problems {
        violations.push(Violation::new(
            "ast-reserved-binding",
            format!("{}: {problem}", path.display()),
        ));
    }
    violations
}

fn validate_row(
    row: &ContractRow,
    file: &syn::File,
    strict: bool,
    expected: &BTreeMap<String, ExpectedRow>,
) -> Vec<Violation> {
    let mut violations = Vec::new();
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
    let expected_production = if expected_crate_bindings(&row.file).is_some() {
        source_production_path(&row.production_entry)
    } else if strict {
        None
    } else {
        Some(row.production_entry.clone())
    };
    if parsed.case != row.case_type
        || expected_production.as_deref() != Some(parsed.production.as_str())
        || parsed.mutation != mutation
        || parsed.control != control
        || parsed.broken != row.broken_variant
    {
        violations.push(Violation::new(
            "ast-source-binding",
            format!(
                "{} source case/mutation/control/broken/production drifted (production `{}` != pinned crate-root path {:?})",
                row.invariant, parsed.production, expected_production
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
                    digest(&canonical(tests[0])),
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
                    value.semantic_digest.clone(),
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
    violations
}

fn emitted_row(row: &ContractRow, file: &syn::File) -> Result<String, String> {
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(value) if value.sig.ident == row.test_fn => Some(value),
            _ => None,
        })
        .ok_or_else(|| "test missing".to_owned())?;
    let mac = direct_test_macro(function, &row.macro_path).map_err(|error| error.message)?;
    let _parsed = parse_invocation(mac, &row.macro_path)?;
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
        digest(&canonical(function)),
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
    let (sources, source_violations) = parse_registered_sources(&rows);
    if !source_violations.is_empty() {
        for violation in source_violations {
            eprintln!("[{}] {}", violation.code, violation.message);
        }
        std::process::exit(1);
    }
    if arguments[0] == "--emit" {
        for row in &rows {
            match emitted_row(row, &sources[&row.file]) {
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
        violations.extend(validate_normalizer_helpers(&sources));
        violations.extend(validate_registered_source_semantics(&rows, &sources));
        if let Some(protocol) = validate_protocol_semantics() {
            violations.push(protocol);
        }
    }
    for (path, file) in &sources {
        violations.extend(validate_source_file(path, file, strict));
    }
    for row in &rows {
        violations.extend(validate_row(row, &sources[&row.file], strict, &expected));
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
