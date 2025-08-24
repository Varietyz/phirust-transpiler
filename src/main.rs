// Copyright 2025 Baleine Jay
// Licensed under the Phicode Non-Commercial License (https://banes-lab.com/licensing)
// Commercial use requires a paid license. See link for details.
mod threat_detector;
use threat_detector::ThreatDetector;
use clap::Parser;
use std::io::{self, Read, Write};
use ahash::{AHashMap, AHashSet};
use regex::{Regex, Captures};
use serde_json;

pub struct SymbolTranspiler {
    mappings: AHashMap<String, String>,
    pattern: Option<Regex>,
    symbol_bytes: Option<AHashSet<u8>>,
}

impl SymbolTranspiler {
    pub fn new() -> Self {
        Self {
            mappings: AHashMap::new(),
            pattern: None,
            symbol_bytes: None,
        }
    }

    pub fn configure(&mut self, mappings: AHashMap<String, String>) -> Result<(), String> {
        self.mappings = mappings;
        if self.mappings.is_empty() {
            self.pattern = None;
            self.symbol_bytes = None;
            return Ok(());
        }

        let mut bytes = AHashSet::new();
        for symbol in self.mappings.keys() {
            for byte in symbol.bytes() {
                if byte > 127 {
                    bytes.insert(byte);
                }
            }
        }
        self.symbol_bytes = Some(bytes);

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
        match &self.symbol_bytes {
            Some(bytes) => {
                let source_bytes = source.as_bytes();
                for chunk in source_bytes.chunks(64) {
                    for &byte in chunk {
                        if byte > 127 && bytes.contains(&byte) {
                            return true;
                        }
                    }
                }
                false
            },
            None => false,
        }
    }

    pub fn transpile(&mut self, source: &str, threat_detector: &ThreatDetector, bypass_security: bool) -> Result<String, String> {
        if !self.contains_symbols(source) {
            return Ok(source.to_string());
        }

        let pattern = match &self.pattern {
            Some(p) => p,
            None => return Ok(source.to_string()),
        };

        let mut blocked = false;
        let result = pattern.replace_all(source, |caps: &Captures| {
            let matched = &caps[1];

            if let Some(python_replacement) = self.mappings.get(matched) {
                if !bypass_security && threat_detector.is_dangerous(python_replacement) {
                    blocked = true;
                    return "SECURITY_BLOCKED".to_string();
                }
                python_replacement.clone()
            } else {
                matched.to_string()
            }
        });

        if blocked {
            return Err("Security: Dangerous pattern detected during transpilation".to_string());
        }

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
    #[arg(long, help = "Bypass threat detection")]
    bypass: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let mappings: AHashMap<String, String> = serde_json::from_str(&cli.symbols)?;

    let threat_detector = ThreatDetector::new()?;

    let mut transpiler = SymbolTranspiler::new();
    transpiler.configure(mappings)?;
    let mut source = String::new();
    io::stdin().read_to_string(&mut source)?;

    let result = transpiler.transpile(&source, &threat_detector, cli.bypass)?;

    if cli.benchmark {
        let start = std::time::Instant::now();
        let _ = transpiler.transpile(&source, &threat_detector, cli.bypass)?;
        let duration = start.elapsed();
        let chars_per_sec = if duration.as_secs_f64() > 0.0 {
            source.len() as f64 / duration.as_secs_f64()
        } else {
            f64::INFINITY
        };
        eprintln!("Transpiled {} chars in {:?}", source.len(), duration);
        eprintln!("Speed: {:.0} chars/sec", chars_per_sec);
    }

    if cli.bypass {
        eprintln!("⚠️  Security bypass enabled - threats not blocked");
    }

    io::stdout().write_all(result.as_bytes())?;
    Ok(())
}