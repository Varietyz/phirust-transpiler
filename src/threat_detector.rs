use aho_corasick::AhoCorasick;

pub struct ThreatDetector {
    detector: AhoCorasick,
}

impl ThreatDetector {
    pub fn new() -> Result<Self, String> {
        let threats = [
            // Current patterns (all good)
            "eval(", "eval (", "exec(", "exec (", "compile(", "compile (",
            "getattr(__builtins__", "getattr(__builtins__,", "globals(", "globals (",
            "locals(", "locals (", "os.system(", "os.system (", "subprocess.",
            "__import__", "vars(", "vars (", "dir(", "dir (", "open(", "open (",
            "input(", "raw_input(",
        ];

        Ok(Self {
            detector: AhoCorasick::new(threats)
                .map_err(|e| format!("Threat detector: {}", e))?
        })
    }

    pub fn is_dangerous(&self, python_code: &str) -> bool {
        self.detector.is_match(python_code)
    }
}