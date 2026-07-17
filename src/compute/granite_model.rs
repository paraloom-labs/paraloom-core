//! A [`ModelRunner`] backed by a local `llama.cpp` server running an open GGUF
//! model.
//!
//! Confidential inference runs open models; the demo target is IBM's Apache-2.0
//! Granite (e.g. `granite-3.3-2b-instruct`, quantized GGUF), which runs on a CPU
//! at a usable speed and so fits inside a CPU-only TEE. The model is served by a
//! `llama-server` process loaded once inside the enclave; this runner sends each
//! decrypted prompt to its local `/completion` endpoint and returns the
//! generated text. The prompt is plaintext only inside the enclave — the server
//! is loopback-only and colocated with the worker. Nothing here is
//! Granite-specific; any GGUF `llama-server` serves works.

use super::confidential_inference::ModelRunner;
use anyhow::{anyhow, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Sends prompts to a local `llama-server` `/completion` endpoint.
pub struct GraniteModelRunner {
    /// Base URL of the local server, e.g. `http://127.0.0.1:8080`.
    endpoint: String,
    /// Maximum tokens to generate per prompt.
    max_tokens: u32,
    /// Sampling temperature.
    temperature: f32,
}

impl GraniteModelRunner {
    /// A runner pointed at a `llama-server` `endpoint`, generating up to 256
    /// tokens at a low temperature by default.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            max_tokens: 256,
            temperature: 0.3,
        }
    }

    /// Cap the generated length.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Set the sampling temperature.
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }
}

impl ModelRunner for GraniteModelRunner {
    fn run(&self, prompt: &[u8]) -> Result<Vec<u8>> {
        let prompt =
            std::str::from_utf8(prompt).map_err(|_| anyhow!("prompt is not valid UTF-8"))?;

        // A blocking loopback request keeps `run` synchronous, so it composes
        // with the worker whether it is called from an async task or not.
        let addr = self
            .endpoint
            .trim_start_matches("http://")
            .trim_end_matches('/');
        let body = serde_json::json!({
            "prompt": prompt,
            "n_predict": self.max_tokens,
            "temperature": self.temperature,
            "stream": false,
        })
        .to_string();
        let request = format!(
            "POST /completion HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );

        let mut stream = TcpStream::connect(addr)
            .map_err(|e| anyhow!("cannot reach llama-server at {addr}: {e}"))?;
        stream.set_read_timeout(Some(Duration::from_secs(180)))?;
        stream.write_all(request.as_bytes())?;
        let mut raw = Vec::new();
        stream.read_to_end(&mut raw)?;

        let response = String::from_utf8_lossy(&raw);
        let json_body = response
            .split_once("\r\n\r\n")
            .map(|(_, body)| body)
            .ok_or_else(|| anyhow!("llama-server response had no body"))?;
        let parsed: serde_json::Value = serde_json::from_str(json_body.trim())
            .map_err(|e| anyhow!("llama-server returned invalid JSON: {e}"))?;
        let content = parsed
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| anyhow!("llama-server response had no content field"))?;
        Ok(content.trim().as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_non_utf8_prompt() {
        // The UTF-8 check happens before any connection is attempted.
        let runner = GraniteModelRunner::new("http://127.0.0.1:8080");
        assert!(runner.run(&[0xff, 0xfe, 0x00]).is_err());
    }

    #[test]
    fn errors_when_no_server_is_listening() {
        // Port 1 is not served; the connection fails cleanly.
        let runner = GraniteModelRunner::new("http://127.0.0.1:1");
        assert!(runner.run(b"hello").is_err());
    }

    /// End-to-end against a real `llama-server`. Ignored by default — run locally
    /// with a server up, e.g.:
    /// `GRANITE_ENDPOINT=http://127.0.0.1:8080 cargo test -- --ignored real_granite`
    #[test]
    #[ignore = "needs a running llama-server"]
    fn real_granite_answers_a_prompt() {
        let endpoint =
            std::env::var("GRANITE_ENDPOINT").expect("set GRANITE_ENDPOINT to a llama-server URL");
        let runner = GraniteModelRunner::new(endpoint).with_max_tokens(16);
        let out = runner
            .run(b"Reply with the single word: ready.")
            .expect("model ran");
        assert!(!out.is_empty());
    }
}
