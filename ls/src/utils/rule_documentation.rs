use yara_x_parser::cst::{Immutable, Node, SyntaxKind};

/// Builder for a Markdown representation of a rule.
pub struct RuleDocumentationBuilder {
    name: String,
    metas: Option<Node<Immutable>>,
    patterns: Option<Node<Immutable>>,
    condition: Option<Node<Immutable>>,
}

impl RuleDocumentationBuilder {
    /// Creates a new builder with the given rule identifier.
    pub fn new(name: &str) -> Self {
        Self {
            name: String::from(name),
            metas: None,
            patterns: None,
            condition: None,
        }
    }

    /// Creates a builder populated from a rule declaration.
    pub fn from_rule(name: &str, rule: &Node<Immutable>) -> Self {
        let mut builder = Self::new(name);

        for child in rule.children() {
            match child.kind() {
                SyntaxKind::META_BLK => builder.set_metas(child),
                SyntaxKind::PATTERNS_BLK => builder.set_patterns(child),
                SyntaxKind::CONDITION_BLK => builder.set_condition(child),
                _ => {}
            }
        }

        builder
    }

    /// Creates the Markdown representation of the rule.
    pub fn get_markdown(&self) -> String {
        let mut markdown = format!("### rule `{}`\n", self.name);

        if let Some(metas) = self.process_metas() {
            markdown.push_str("```\n");
            markdown.push_str(&metas);
            markdown.push_str("\n```\n");
        }

        markdown
    }

    /// Processes the meta block and returns its Markdown representation.
    fn process_metas(&self) -> Option<String> {
        Some(
            self.metas
                .as_ref()?
                // All children in META_BLK should be META_DEF.
                .children()
                .map(|node| format!("{}\n", node.text()))
                .collect(),
        )
    }

    /// Sets the meta block of the rule.
    pub fn set_metas(&mut self, meta: Node<Immutable>) {
        self.metas = Some(meta);
    }

    /// Sets the patterns block of the rule.
    pub fn set_patterns(&mut self, patterns: Node<Immutable>) {
        self.patterns = Some(patterns);
    }

    /// Sets the condition block of the rule.
    pub fn set_condition(&mut self, condition: Node<Immutable>) {
        self.condition = Some(condition);
    }
}
