use clap::Parser;
use std::io::{self, Read, Write};
use ahash::{AHashMap, AHashSet};
use regex::{Regex, Captures};
use serde_json;
pub struct SymbolTranspiler {
    mappings: AHashMap<String, String>,
    pattern: Option<Regex>,
    symbol_chars: Option<AHashSet<char>>,
}
impl SymbolTranspiler {
    pub fn new() -> Self {
        Self { 
            mappings: AHashMap::new(),
            pattern: None,
            symbol_chars: None,
        }
    }
    pub fn configure(&mut self, mappings: AHashMap<String, String>) -> Result<(), String> {
        self.mappings = mappings;
        if self.mappings.is_empty() {
            self.pattern = None;
            self.symbol_chars = None;
            return Ok(());
        }
        let mut chars = AHashSet::new();
        for symbol in self.mappings.keys() {
            for ch in symbol.chars() {
                chars.insert(ch);
            }
        }
        self.symbol_chars = Some(chars);
        let mut symbols: Vec<_> = self.mappings.keys().cloned().collect();
        symbols.sort_by_key(|s| std::cmp::Reverse(s.len()));
        let escaped_symbols: Vec<String> = symbols.iter()
            .map(|s| {
                if s.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    format!(r"\b{}\b", regex::escape(s))
                } else {
                    regex::escape(s)
                }
            })
            .collect();
        let pattern_str = format!("({})", escaped_symbols.join("|"));
        self.pattern = Some(
            Regex::new(&pattern_str)
                .map_err(|e| format!("Regex compilation failed: {}", e))?
        );
        Ok(())
    }
    fn contains_symbols(&self, source: &str) -> bool {
        match &self.symbol_chars {
            Some(chars) => source.chars().any(|c| chars.contains(&c)),
            None => false,
        }
    }
    pub fn transpile(&mut self, source: &str) -> Result<String, String> {
        if !self.contains_symbols(source) {
            return Ok(source.to_string());
        }
        let pattern = match &self.pattern {
            Some(p) => p,
            None => return Ok(source.to_string()),
        };
        let result = pattern.replace_all(source, |caps: &Captures| {
            let matched = &caps[1];
            self.mappings.get(matched)
                .cloned()
                .unwrap_or_else(|| matched.to_string())
        });
        Ok(result.to_string())
    }
}
#[derive(Parser)]
#[command(name = "phicode-transpiler")]
#[command(about = "Fast symbolic transpiler for PhiCode")]
struct Cli {
    #[arg(short, long, help = "JSON mapping of symbols to replacements")]
    symbols: String,
    #[arg(long, help = "Show performance benchmarks")]
    benchmark: bool,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mappings: AHashMap<String, String> = serde_json::from_str(&cli.symbols)
        .map_err(|e| format!("Invalid JSON in symbols: {}", e))?;
    let mut transpiler = SymbolTranspiler::new();
    transpiler.configure(mappings)?;
    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;
    if cli.benchmark {
        let start = std::time::Instant::now();
        let result = transpiler.transpile(&source)?;
        let duration = start.elapsed();
        let chars_per_sec = if duration.as_secs_f64() > 0.0 {
            source.len() as f64 / duration.as_secs_f64()
        } else {
            f64::INFINITY
        };
        eprintln!("Transpiled {} chars in {:?}", source.len(), duration);
        eprintln!("Speed: {:.0} chars/sec", chars_per_sec);
        io::stdout().write_all(result.as_bytes())?;
    } else {
        let result = transpiler.transpile(&source)?;
        io::stdout().write_all(result.as_bytes())?;
    }

    Ok(())
}