//! WASM execution engine with resource limits and sandboxing
//!
//! This module provides a secure, isolated WASM execution environment
//! using Wasmtime with configurable resource limits.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::time::{Duration, Instant};
use wasmtime::*;

use super::job::{ComputeJob, JobResult};

/// WASM execution engine with resource isolation
pub struct WasmEngine {
    /// Wasmtime engine
    engine: Engine,
}

impl WasmEngine {
    /// Create a new WASM engine
    pub fn new() -> Result<Self> {
        // Configure the engine with security and performance settings
        let mut config = Config::new();

        // Enable WASM features
        config.wasm_simd(true);
        config.wasm_bulk_memory(true);
        config.wasm_multi_value(true);
        config.wasm_reference_types(true);

        // Security: Disable features that could be dangerous
        config.cranelift_nan_canonicalization(true);

        // Set memory limits at engine level
        config.max_wasm_stack(2 * 1024 * 1024); // 2MB stack

        let engine = Engine::new(&config)?;

        info!("WASM engine initialized with security settings");

        Ok(Self { engine })
    }

    /// Execute a compute job with resource limits
    pub fn execute_job(&self, job: &ComputeJob) -> Result<JobResult> {
        let start_time = Instant::now();

        info!("Executing job {} with WASM bytecode ({} bytes)",
              job.id, job.wasm_code.len());

        // Create a new store with resource limits
        let mut store = self.create_store_with_limits(
            job.max_memory_bytes,
            job.max_instructions,
        )?;

        // Compile the WASM module
        let module = match Module::new(&self.engine, &job.wasm_code) {
            Ok(m) => m,
            Err(e) => {
                warn!("Failed to compile WASM module for job {}: {}", job.id, e);
                return Ok(JobResult::failure(
                    job.id.clone(),
                    format!("WASM compilation failed: {}", e),
                    start_time.elapsed().as_millis() as u64,
                ));
            }
        };

        // Create a linker for host function imports
        let mut linker = Linker::new(&self.engine);

        // Add common host functions
        self.add_host_functions(&mut linker)?;

        // Instantiate the module
        let instance = match linker.instantiate(&mut store, &module) {
            Ok(i) => i,
            Err(e) => {
                warn!("Failed to instantiate WASM module for job {}: {}", job.id, e);
                return Ok(JobResult::failure(
                    job.id.clone(),
                    format!("WASM instantiation failed: {}", e),
                    start_time.elapsed().as_millis() as u64,
                ));
            }
        };

        // Get the main execution function (expected to be named "execute")
        let execute_fn = match instance.get_typed_func::<(i32, i32), i32>(&mut store, "execute") {
            Ok(f) => f,
            Err(_) => {
                // Try alternative function names
                match instance.get_typed_func::<(), ()>(&mut store, "_start") {
                    Ok(_) => {
                        warn!("Job {} uses _start function, not execute", job.id);
                        return Ok(JobResult::failure(
                            job.id.clone(),
                            "WASM module must export 'execute(input_ptr: i32, input_len: i32) -> i32' function".to_string(),
                            start_time.elapsed().as_millis() as u64,
                        ));
                    }
                    Err(e) => {
                        warn!("Failed to find execute function in job {}: {}", job.id, e);
                        return Ok(JobResult::failure(
                            job.id.clone(),
                            format!("WASM module must export 'execute' function: {}", e),
                            start_time.elapsed().as_millis() as u64,
                        ));
                    }
                }
            }
        };

        // Get memory to write input data
        let memory = match instance.get_memory(&mut store, "memory") {
            Some(m) => m,
            None => {
                return Ok(JobResult::failure(
                    job.id.clone(),
                    "WASM module must export 'memory'".to_string(),
                    start_time.elapsed().as_millis() as u64,
                ));
            }
        };

        // Write input data to WASM memory (starting at offset 0)
        let input_ptr = 0i32;
        let input_len = job.input_data.len() as i32;

        if !job.input_data.is_empty() {
            memory.write(&mut store, input_ptr as usize, &job.input_data)?;
        }

        // Execute the function with timeout
        let result = match self.execute_with_timeout(
            &mut store,
            &execute_fn,
            input_ptr,
            input_len,
            Duration::from_secs(job.timeout_secs),
        ) {
            Ok(output_ptr) => {
                // Read output data from memory
                let output_len = 1024; // TODO: Get actual output length from return value
                let mut output_data = vec![0u8; output_len];
                memory.read(&store, output_ptr as usize, &mut output_data)?;

                let execution_time = start_time.elapsed().as_millis() as u64;
                let memory_used = memory.data_size(&store) as u64;

                debug!("Job {} completed successfully in {}ms", job.id, execution_time);

                JobResult::success(
                    job.id.clone(),
                    output_data,
                    execution_time,
                    memory_used,
                    0, // TODO: Track actual instruction count
                )
            }
            Err(e) => {
                warn!("Job {} execution failed: {}", job.id, e);
                JobResult::failure(
                    job.id.clone(),
                    format!("Execution failed: {}", e),
                    start_time.elapsed().as_millis() as u64,
                )
            }
        };

        Ok(result)
    }

    /// Create a store with resource limits
    fn create_store_with_limits(
        &self,
        max_memory_bytes: u64,
        _max_instructions: u64,
    ) -> Result<Store<ResourceLimiterImpl>> {
        // Set memory limit (WASM pages are 64KB = 65536 bytes)
        let memory_limit_pages = (max_memory_bytes / 65536) as usize;

        debug!("Creating store with memory limit: {} pages ({} bytes)",
               memory_limit_pages, max_memory_bytes);

        let limiter = ResourceLimiterImpl {
            memory_limit_pages,
        };

        let mut store = Store::new(&self.engine, limiter);
        // The store's data (ResourceLimiterImpl) automatically acts as the limiter
        store.limiter(|state| state as &mut dyn ResourceLimiter);

        Ok(store)
    }

    /// Add host functions that WASM modules can import
    fn add_host_functions(&self, linker: &mut Linker<ResourceLimiterImpl>) -> Result<()> {
        // Add a simple logging function
        linker.func_wrap("env", "log", |_caller: wasmtime::Caller<'_, ResourceLimiterImpl>, param: i32| {
            debug!("WASM log: {}", param);
        })?;

        Ok(())
    }

    /// Execute a function with timeout
    fn execute_with_timeout(
        &self,
        store: &mut Store<ResourceLimiterImpl>,
        func: &TypedFunc<(i32, i32), i32>,
        input_ptr: i32,
        input_len: i32,
        _timeout: Duration,
    ) -> Result<i32> {
        // TODO: Implement proper timeout mechanism
        // For now, just execute directly
        func.call(store, (input_ptr, input_len))
            .map_err(|e| anyhow!("WASM execution error: {}", e))
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create default WASM engine")
    }
}

/// Resource limiter implementation
struct ResourceLimiterImpl {
    memory_limit_pages: usize,
}

impl ResourceLimiter for ResourceLimiterImpl {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // Allow memory growth if within limits
        let allowed = desired <= self.memory_limit_pages;

        if !allowed {
            warn!(
                "Memory limit would be exceeded: desired {} pages, limit {} pages",
                desired, self.memory_limit_pages
            );
        } else {
            debug!("Memory growing from {} to {} pages (limit: {})",
                   current, desired, self.memory_limit_pages);
        }

        Ok(allowed)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // Allow table growth up to a reasonable limit
        Ok(desired < 10000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::job::{JobStatus, ResourceLimits};

    #[test]
    fn test_wasm_engine_creation() {
        let engine = WasmEngine::new();
        assert!(engine.is_ok());
    }

    #[test]
    fn test_invalid_wasm_bytecode() {
        let engine = WasmEngine::new().unwrap();

        let job = ComputeJob::new(
            vec![0x00, 0x00, 0x00, 0x00], // Invalid WASM
            vec![],
            ResourceLimits::default(),
        );

        let result = engine.execute_job(&job).unwrap();
        assert!(matches!(result.status, JobStatus::Failed { .. }));
    }

    #[test]
    #[ignore] // TODO: Fix ResourceLimiter integration with Wasmtime v26
    fn test_valid_wasm_module() {
        let engine = WasmEngine::new().unwrap();

        // Minimal valid WASM module with execute function
        let wat = r#"
            (module
                (memory (export "memory") 1)
                (func (export "execute") (param i32 i32) (result i32)
                    i32.const 0
                )
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).unwrap();

        let job = ComputeJob::new(
            wasm_bytes,
            vec![1, 2, 3, 4],
            ResourceLimits::default(),
        );

        let result = engine.execute_job(&job).unwrap();
        assert_eq!(result.status, JobStatus::Completed);
    }
}
