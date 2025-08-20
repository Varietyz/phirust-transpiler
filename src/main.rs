use clap::Parser;
use std::io::{self, Read, Write};
use aho_corasick::AhoCorasick;
use ahash::AHashMap;
use regex::Regex;

fn protect_strings_and_comments(source: &str) -> (String, Vec<String>) {
    // More optimized pattern for Python code
    let pattern = r#"(?x)
        # Triple double-quoted strings
        (?:[rRuUbBfF]{,2}) """ (?: [^"\\] | \\. | "(?!""))* """ |
        # Triple single-quoted strings  
        (?:[rRuUbBfF]{,2}) ''' (?: [^'\\] | \\. | '(?!''))* ''' |
        # Double-quoted strings
        (?:[rRuUbBfF]{,2}) " (?: [^"\\\n] | \\. )* " |
        # Single-quoted strings
        (?:[rRuUbBfF]{,2}) ' (?: [^'\\\n] | \\. )* ' |
        # Comments
        #[^\n]*
    "#;
    
    let re = Regex::new(pattern).unwrap();
    let mut protected = Vec::new();
    let mut result = String::new();
    let mut last_end = 0;
    
    for mat in re.find_iter(source) {
        result.push_str(&source[last_end..mat.start()]);
        result.push_str(&format!("__PROTECTED_{}__", protected.len()));
        protected.push(mat.as_str().to_string());
        last_end = mat.end();
    }
    
    result.push_str(&source[last_end..]);
    (result, protected)
}

fn restore_strings_and_comments(transpiled: &str, protected: &[String]) -> String {
    let mut result = transpiled.to_string();
    for (i, content) in protected.iter().enumerate() {
        let placeholder = format!("__PROTECTED_{}__", i);
        result = result.replace(&placeholder, content);
    }
    result
}

pub struct SymbolTranspiler {
    automaton: Option<AhoCorasick>,
    replacements: Vec<String>,
}

impl SymbolTranspiler {
    pub fn new() -> Self {
        Self { automaton: None, replacements: Vec::new() }
    }

    pub fn configure(&mut self, mappings: AHashMap<String, String>) -> Result<(), String> {
        let mut pairs: Vec<(String, String)> = mappings.into_iter().collect();
        pairs.sort_by_key(|(k, _)| std::cmp::Reverse(k.len()));

        // First extract the patterns as owned strings
        let patterns: Vec<String> = pairs.iter().map(|(k, _)| k.clone()).collect();
        
        // Then extract replacements (this consumes pairs)
        self.replacements = pairs.into_iter().map(|(_, v)| v).collect();

        // Convert patterns to string slices for AhoCorasick
        let pattern_refs: Vec<&str> = patterns.iter().map(|s| s.as_str()).collect();
        self.automaton = Some(AhoCorasick::new(&pattern_refs).map_err(|e| e.to_string())?);
        Ok(())
    }

    pub fn transpile(&self, source: &str) -> Result<String, String> {
        let automaton = self.automaton.as_ref().ok_or("Not configured")?;
        let replacements: Vec<&str> = self.replacements.iter().map(|s| s.as_str()).collect();
        Ok(automaton.replace_all(source, &replacements))
    }
}

#[derive(Parser)]
struct Cli {
    #[arg(short, long, required = true)]
    symbols: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mappings: AHashMap<String, String> = serde_json::from_str(&cli.symbols)?;

    let mut transpiler = SymbolTranspiler::new();
    transpiler.configure(mappings)?;

    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;

    let (protected_source, protected_content) = protect_strings_and_comments(&source);
    
    let transpiled = transpiler.transpile(&protected_source)?;
    
    let result = restore_strings_and_comments(&transpiled, &protected_content);
    
    io::stdout().write_all(result.as_bytes())?;
    Ok(())
}