use async_lsp::lsp_types::{
    Location, OneOf, SymbolKind, Url, WorkspaceLocation, WorkspaceSymbol,
    WorkspaceSymbolResponse,
};
use std::sync::Arc;
use yara_x_parser::cst::{Immutable, Node, SyntaxKind};

use crate::{
    documents::storage::DocumentStorage, utils::position::node_to_range,
};

pub fn workspace_symbol(
    documents: Arc<DocumentStorage>,
    workspace_resolve_location: bool,
) -> Option<WorkspaceSymbolResponse> {
    // If client does support resolve for workspace symbols, then the language server
    // can compute the location of the symbols later. Otherwise, language server has
    // to compute the position right away here.
    let location = if workspace_resolve_location {
        |uri: Url, _node: Node<Immutable>| {
            OneOf::Right(WorkspaceLocation { uri })
        }
    } else {
        |uri: Url, node: Node<Immutable>| {
            OneOf::Left(Location { uri, range: node_to_range(&node).unwrap() })
        }
    };

    Some(WorkspaceSymbolResponse::Nested(
        documents
            .workspace_rules()?
            .map(|(rule_decl, uri)| WorkspaceSymbol {
                // Find the name of the rule
                name: rule_decl
                    .children_with_tokens()
                    .find_map(|ident| {
                        if ident.kind() == SyntaxKind::IDENT {
                            ident.into_token()
                        } else {
                            None
                        }
                    })
                    .map(|token| token.text().to_string())
                    .unwrap_or_default(),
                // The same kind for rules as in Document Symbols feature
                kind: SymbolKind::FUNCTION,
                tags: None,
                container_name: None,
                location: location(uri, rule_decl),
                data: None,
            })
            .collect(),
    ))
}

pub fn workspace_symbol_resolve(
    documents: Arc<DocumentStorage>,
    symbol: WorkspaceSymbol,
) -> WorkspaceSymbol {
    if let OneOf::Right(WorkspaceLocation { uri }) = &symbol.location
        && let Some(rule) = documents.workspace_resolve(uri, &symbol.name)
    {
        WorkspaceSymbol {
            location: OneOf::Left(Location {
                uri: uri.clone(),
                range: node_to_range(&rule).unwrap(),
            }),
            ..symbol
        }
    } else {
        symbol
    }
}
