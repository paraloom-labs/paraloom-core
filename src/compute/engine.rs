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

        // Enable epoch interruption for timeouts
        config.epoch_interruption(true);

        // Enable fuel consumption tracking for instruction counting
        config.consume_fuel(true);

        let engine = Engine::new(&config)?;

        info!(
            "WASM engine initialized with security settings, epoch interruption, and fuel tracking"
        );

        Ok(Self { engine })
    }

    /// Execute a compute job with resource limits
    pub fn execute_job(&self, job: &ComputeJob) -> Result<JobResult> {
        let start_time = Instant::now();

        info!(
            "Executing job {} with WASM bytecode ({} bytes)",
            job.id,
            job.wasm_code.len()
        );

        // Create a new store with resource limits
        let mut store =
            self.create_store_with_limits(job.max_memory_bytes, job.max_instructions)?;

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
                warn!(
                    "Failed to instantiate WASM module for job {}: {}",
                    job.id, e
                );
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

        // Get initial fuel to calculate consumption
        let initial_fuel = store.get_fuel().unwrap_or(0);

        // Execute the function with timeout
        let result = match self.execute_with_timeout(
            &mut store,
            &execute_fn,
            input_ptr,
            input_len,
            Duration::from_secs(job.timeout_secs),
        ) {
            Ok(output_ptr) => {
                // Calculate instruction count from fuel consumption
                let remaining_fuel = store.get_fuel().unwrap_or(0);
                let instructions_executed = initial_fuel.saturating_sub(remaining_fuel);

                // Read output data from memory
                // The output_ptr is the starting position, we need to determine length
                // For now, read up to 64KB or until we hit zeros (depends on contract)
                let max_output_size = 65536; // 64KB max output
                let output_len =
                    if output_ptr >= 0 && (output_ptr as usize) < memory.data_size(&store) {
                        // Read a reasonable amount of data
                        // In real scenarios, the WASM module should return length or use a convention
                        std::cmp::min(
                            max_output_size,
                            memory.data_size(&store) - (output_ptr as usize),
                        )
                    } else {
                        0
                    };

                let mut output_data = vec![0u8; output_len];
                if output_len > 0 {
                    memory.read(&store, output_ptr as usize, &mut output_data)?;
                }

                let execution_time = start_time.elapsed().as_millis() as u64;
                let memory_used = memory.data_size(&store) as u64;

                debug!(
                    "Job {} completed successfully in {}ms, {} instructions executed",
                    job.id, execution_time, instructions_executed
                );

                JobResult::success(
                    job.id.clone(),
                    output_data,
                    execution_time,
                    memory_used,
                    instructions_executed,
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
        max_instructions: u64,
    ) -> Result<Store<ResourceLimiterImpl>> {
        debug!(
            "Creating store with memory limit: {} bytes, instruction limit: {}",
            max_memory_bytes, max_instructions
        );

        let limiter = ResourceLimiterImpl {
            memory_limit_bytes: max_memory_bytes as usize,
        };

        let mut store = Store::new(&self.engine, limiter);

        // Set the limiter on the store
        store.limiter(|state| state);

        // Set fuel limit for instruction counting
        // Each fuel unit roughly corresponds to one WASM instruction
        store.set_fuel(max_instructions)?;

        Ok(store)
    }

    /// Add host functions that WASM modules can import
    fn add_host_functions(&self, linker: &mut Linker<ResourceLimiterImpl>) -> Result<()> {
        // Add a simple logging function
        linker.func_wrap(
            "env",
            "log",
            |_caller: wasmtime::Caller<'_, ResourceLimiterImpl>, param: i32| {
                debug!("WASM log: {}", param);
            },
        )?;

        Ok(())
    }

    /// Execute a function with timeout
    fn execute_with_timeout(
        &self,
        store: &mut Store<ResourceLimiterImpl>,
        func: &TypedFunc<(i32, i32), i32>,
        input_ptr: i32,
        input_len: i32,
        timeout: Duration,
    ) -> Result<i32> {
        // Set epoch deadline for timeout
        // Deadline is current epoch + timeout in ticks (1 tick = 1ms approximately)
        let timeout_ticks = timeout.as_millis() as u64;
        store.set_epoch_deadline(timeout_ticks);

        // Start epoch incrementing in background
        let engine_handle = self.engine.clone();
        let timeout_duration = timeout;
        let epoch_thread = std::thread::spawn(move || {
            let start = Instant::now();
            while start.elapsed() < timeout_duration {
                engine_handle.increment_epoch();
                std::thread::sleep(Duration::from_millis(1));
            }
        });

        // Execute the function
        let result = func.call(store, (input_ptr, input_len)).map_err(|e| {
            if e.to_string().contains("epoch") {
                anyhow!("WASM execution timeout after {:?}", timeout)
            } else {
                anyhow!("WASM execution error: {}", e)
            }
        });

        // Clean up epoch thread (it will finish naturally)
        drop(epoch_thread);

        result
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        Self::new().expect("Failed to create default WASM engine")
    }
}

/// Resource limiter implementation
struct ResourceLimiterImpl {
    memory_limit_bytes: usize,
}

impl ResourceLimiter for ResourceLimiterImpl {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        // In modern Wasmtime, parameters are in BYTES, not pages
        let allowed = desired <= self.memory_limit_bytes;

        if !allowed {
            warn!(
                "Memory limit would be exceeded: desired {} bytes, limit {} bytes",
                desired, self.memory_limit_bytes
            );
        } else {
            debug!(
                "Memory growing from {} to {} bytes (limit: {})",
                current, desired, self.memory_limit_bytes
            );
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

        let job = ComputeJob::new(wasm_bytes, vec![1, 2, 3, 4], ResourceLimits::default());

        let result = engine.execute_job(&job).unwrap();
        assert_eq!(result.status, JobStatus::Completed);
    }
}
