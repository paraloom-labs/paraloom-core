//! WASM execution engine with resource limits and sandboxing
//!
//! This module provides a secure, isolated WASM execution environment
//! using Wasmtime with configurable resource limits.

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use wasmtime::*;

use super::job::{ComputeJob, JobResult};

/// Maximum bytes copied out of a WASM module's memory after a job
/// returns. Audit (#71) flagged the unsafe shape this constant
/// guards: a malicious module could otherwise return an output
/// pointer that walks past the end of its linear memory.
pub const MAX_WASM_OUTPUT_SIZE: usize = 65_536;

/// Decide how many bytes to copy from a WASM module's linear memory
/// starting at `output_ptr`, given the module's current `memory_size`
/// and an upstream `max_output_size` cap. Pure / total / panic-free
/// for any `(i32, usize, usize)` triple — the engine relies on this
/// to keep a malicious output pointer from reading out of bounds, so
/// the property is fuzzed under `fuzz/fuzz_targets/wasm_output_len`.
pub fn wasm_output_len(output_ptr: i32, memory_size: usize, max_output_size: usize) -> usize {
    if output_ptr >= 0 && (output_ptr as usize) < memory_size {
        std::cmp::min(max_output_size, memory_size - (output_ptr as usize))
    } else {
        0
    }
}

/// Shared state coordinating a single wall-clock epoch ticker thread per `WasmEngine`.
#[derive(Default)]
struct EpochTickerState {
    /// Number of currently executing WASM calls on this engine.
    active_jobs: usize,
    /// Whether the background epoch ticker thread is currently running.
    ticker_running: bool,
}

/// RAII guard that keeps the engine's wall-clock epoch ticker running while a WASM
/// call is in flight and stops it as soon as the last active call finishes.
struct ActiveEpochGuard {
    ticker_state: Arc<(Mutex<EpochTickerState>, Condvar)>,
}

impl ActiveEpochGuard {
    fn acquire(engine: &Engine, ticker_state: &Arc<(Mutex<EpochTickerState>, Condvar)>) -> Self {
        let mut state = ticker_state.0.lock().unwrap();
        state.active_jobs += 1;

        if !state.ticker_running {
            state.ticker_running = true;
            let engine_handle = engine.clone();
            let ticker_state_clone = Arc::clone(ticker_state);

            std::thread::spawn(move || {
                let mut state = ticker_state_clone.0.lock().unwrap();
                let mut last_tick = Instant::now();

                loop {
                    if state.active_jobs == 0 {
                        state.ticker_running = false;
                        break;
                    }

                    let (new_state, _) = ticker_state_clone
                        .1
                        .wait_timeout(state, Duration::from_millis(1))
                        .unwrap();
                    state = new_state;

                    if state.active_jobs == 0 {
                        state.ticker_running = false;
                        break;
                    }

                    // Advance the engine epoch by the actual wall-clock milliseconds
                    // elapsed since `last_tick`. OS sleep granularity is often >1ms
                    // (~1.5-2ms on Linux/macOS, ~15.6ms on Windows), so advancing 1 tick
                    // per sleep iteration would fall short of `timeout_ticks` and never
                    // trigger the store's epoch deadline.
                    let now = Instant::now();
                    let elapsed_ms = now.duration_since(last_tick).as_millis() as u64;
                    if elapsed_ms > 0 {
                        for _ in 0..elapsed_ms {
                            engine_handle.increment_epoch();
                        }
                        last_tick += Duration::from_millis(elapsed_ms);
                    }
                }
            });
        }

        Self {
            ticker_state: Arc::clone(ticker_state),
        }
    }
}

impl Drop for ActiveEpochGuard {
    fn drop(&mut self) {
        let mut state = self.ticker_state.0.lock().unwrap();
        state.active_jobs = state.active_jobs.saturating_sub(1);
        if state.active_jobs == 0 {
            self.ticker_state.1.notify_all();
        }
    }
}

#[derive(Debug)]
enum ExecutionFailure {
    Timeout(Duration),
    Runtime(anyhow::Error),
}

fn is_epoch_interrupt(err: &anyhow::Error) -> bool {
    if matches!(err.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
        return true;
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("epoch") || msg.contains("wasm trap: interrupt")
}

/// WASM execution engine with resource isolation
pub struct WasmEngine {
    /// Wasmtime engine
    engine: Engine,
    /// Shared wall-clock epoch ticker coordinator
    ticker_state: Arc<(Mutex<EpochTickerState>, Condvar)>,
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

        Ok(Self {
            engine,
            ticker_state: Arc::new((Mutex::new(EpochTickerState::default()), Condvar::new())),
        })
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
            if let Err(e) = memory.write(&mut store, input_ptr as usize, &job.input_data) {
                warn!(
                    "Failed to write input data ({} bytes) to WASM memory for job {}: {}",
                    job.input_data.len(),
                    job.id,
                    e
                );
                return Ok(JobResult::failure(
                    job.id.clone(),
                    format!("Failed to write input data to WASM memory: {}", e),
                    start_time.elapsed().as_millis() as u64,
                ));
            }
        }

        // Get initial fuel to calculate consumption
        let initial_fuel = store.get_fuel().unwrap_or(0);

        // Execute the function with timeout
        let result = match self.execute_with_timeout_internal(
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

                let output_len =
                    wasm_output_len(output_ptr, memory.data_size(&store), MAX_WASM_OUTPUT_SIZE);

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
            Err(ExecutionFailure::Timeout(timeout)) => {
                warn!("Job {} timed out after {:?}", job.id, timeout);
                JobResult::timed_out(
                    job.id.clone(),
                    job.timeout_secs,
                    start_time.elapsed().as_millis() as u64,
                )
            }
            Err(ExecutionFailure::Runtime(e)) => {
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
    fn execute_with_timeout_internal(
        &self,
        store: &mut Store<ResourceLimiterImpl>,
        func: &TypedFunc<(i32, i32), i32>,
        input_ptr: i32,
        input_len: i32,
        timeout: Duration,
    ) -> std::result::Result<i32, ExecutionFailure> {
        if timeout.is_zero() {
            return Err(ExecutionFailure::Timeout(timeout));
        }

        // Set epoch deadline for timeout (1 tick = 1ms of wall-clock time)
        let timeout_ticks = timeout.as_millis().max(1) as u64;
        store.set_epoch_deadline(timeout_ticks);

        // Ensure the shared wall-clock epoch ticker is running while this call is active,
        // and automatically stop/notify it when `_epoch_guard` is dropped.
        let _epoch_guard = ActiveEpochGuard::acquire(&self.engine, &self.ticker_state);

        func.call(store, (input_ptr, input_len)).map_err(|e| {
            if is_epoch_interrupt(&e) {
                ExecutionFailure::Timeout(timeout)
            } else {
                ExecutionFailure::Runtime(anyhow!("WASM execution error: {}", e))
            }
        })
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

    #[test]
    fn test_infinite_loop_wasm_times_out_with_timed_out_status() {
        let engine = WasmEngine::new().unwrap();

        let wat = r#"
            (module
                (memory (export "memory") 1)
                (func (export "execute") (param i32 i32) (result i32)
                    (loop $inf
                        br $inf
                    )
                    i32.const 0
                )
            )
        "#;

        let wasm_bytes = wat::parse_str(wat).unwrap();
        let limits = ResourceLimits {
            max_memory_bytes: 64 * 1024 * 1024,
            // Very high instruction budget so only wall-clock epoch timeout can stop it
            max_instructions: u64::MAX / 2,
            timeout_secs: 1,
        };
        let job = ComputeJob::new(wasm_bytes, vec![], limits);

        let start = Instant::now();
        let result = engine.execute_job(&job).unwrap();
        let elapsed = start.elapsed();

        assert_eq!(result.status, JobStatus::TimedOut);
        assert!(
            elapsed < Duration::from_secs(5),
            "infinite loop job should time out promptly around 1s, took {:?}",
            elapsed
        );
    }

    #[test]
    fn test_completed_jobs_stop_epoch_ticker_and_do_not_accelerate_later_jobs() {
        let engine = WasmEngine::new().unwrap();

        let fast_wat = r#"
            (module
                (memory (export "memory") 1)
                (func (export "execute") (param i32 i32) (result i32)
                    i32.const 0
                )
            )
        "#;
        let fast_wasm = wat::parse_str(fast_wat).unwrap();

        // Run 30 fast jobs with 30s timeouts. Previously each job leaked a detached
        // background thread incrementing the shared Engine epoch for 30s.
        for _ in 0..30 {
            let job = ComputeJob::new(fast_wasm.clone(), vec![], ResourceLimits::default());
            let result = engine.execute_job(&job).unwrap();
            assert_eq!(result.status, JobStatus::Completed);
        }

        // Wait briefly for the ticker thread to observe active_jobs == 0 and exit.
        std::thread::sleep(Duration::from_millis(20));
        {
            let state = engine.ticker_state.0.lock().unwrap();
            assert_eq!(state.active_jobs, 0);
            assert!(
                !state.ticker_running,
                "epoch ticker thread must exit once all active jobs complete"
            );
        }

        // Verify the engine epoch is no longer advancing while idle.
        let idle_wat = r#"
            (module
                (memory (export "memory") 1)
                (func (export "execute") (param i32 i32) (result i32)
                    (local $i i32)
                    (block $done
                        (loop $busy
                            (local.set $i (i32.add (local.get $i) (i32.const 1)))
                            (br_if $done (i32.ge_u (local.get $i) (i32.const 5000000)))
                            (br $busy)
                        )
                    )
                    i32.const 0
                )
            )
        "#;
        let busy_wasm = wat::parse_str(idle_wat).unwrap();
        let job = ComputeJob::new(
            busy_wasm,
            vec![],
            ResourceLimits {
                max_memory_bytes: 64 * 1024 * 1024,
                max_instructions: 1_000_000_000,
                timeout_secs: 1,
            },
        );
        let result = engine.execute_job(&job).unwrap();
        assert_eq!(result.status, JobStatus::Completed);
    }

    #[test]
    fn test_undersized_wasm_memory_returns_failed_job_result() {
        let engine = WasmEngine::new().unwrap();

        // Module exports 0 pages of linear memory, so writing non-empty input fails.
        let wat = r#"
            (module
                (memory (export "memory") 0)
                (func (export "execute") (param i32 i32) (result i32)
                    i32.const 0
                )
            )
        "#;
        let wasm_bytes = wat::parse_str(wat).unwrap();
        let job = ComputeJob::new(wasm_bytes, vec![1, 2, 3, 4], ResourceLimits::default());

        let result = engine
            .execute_job(&job)
            .expect("undersized WASM memory should return Ok(JobResult::failure), not Err");
        assert!(matches!(result.status, JobStatus::Failed { .. }));
    }
}
