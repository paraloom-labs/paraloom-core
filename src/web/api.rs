//! REST API for task management

use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::coordinator::Coordinator;
use crate::task::{TaskId, TaskStatus, TaskType};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskRequest {
    pub task_type: String,
    pub start: u64,
    pub end: u64,
    pub algorithm: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTaskResponse {
    pub task_id: TaskId,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatusResponse {
    pub task_id: TaskId,
    pub status: String,
    pub message: String,
}

#[derive(Clone)]
pub struct ApiState {
    pub coordinator: Arc<Coordinator>,
}

fn validate_submit_request(req: &SubmitTaskRequest) -> Result<TaskType, StatusCode> {
    let kind = req.task_type.trim().to_ascii_lowercase();
    if !matches!(
        kind.as_str(),
        "hash" | "hash_calculation" | "hashcalculation"
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.start >= req.end {
        return Err(StatusCode::BAD_REQUEST);
    }
    let algorithm = req.algorithm.trim().to_ascii_lowercase();
    if !matches!(algorithm.as_str(), "sha256" | "blake3") {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(TaskType::HashCalculation {
        start: req.start,
        end: req.end,
        algorithm,
    })
}

async fn submit_task(
    Extension(state): Extension<ApiState>,
    Json(req): Json<SubmitTaskRequest>,
) -> Result<Json<SubmitTaskResponse>, StatusCode> {
    log::info!("API: Received task submission request: {:?}", req);

    let task_type = validate_submit_request(&req)?;

    // Submit task synchronously (sequential chunk sending has timeout protection)
    match state.coordinator.submit_task(task_type).await {
        Ok(task_id) => {
            log::info!("API: Task submitted successfully: {}", task_id);
            Ok(Json(SubmitTaskResponse {
                task_id,
                status: "submitted".to_string(),
            }))
        }
        Err(e) => {
            log::error!("API: Failed to submit task: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn get_task_status(
    Path(task_id): Path<String>,
    Extension(state): Extension<ApiState>,
) -> Json<TaskStatusResponse> {
    log::info!("API: Task status request: {}", task_id);

    let snapshot = state.coordinator.snapshot().await;
    if let Some(task) = snapshot.active_tasks.get(&task_id) {
        let (status, message) = match &task.status {
            TaskStatus::Pending => ("pending".to_string(), "Task is pending".to_string()),
            TaskStatus::Assigned | TaskStatus::Running => (
                "processing".to_string(),
                "Task is being processed".to_string(),
            ),
            TaskStatus::Completed => ("completed".to_string(), "Task completed".to_string()),
            TaskStatus::Failed { error } => ("failed".to_string(), format!("Task failed: {error}")),
        };
        return Json(TaskStatusResponse {
            task_id,
            status,
            message,
        });
    }

    let chunk_ids: Vec<&TaskId> = snapshot
        .parent_tasks
        .iter()
        .filter_map(|(cid, pid)| if pid == &task_id { Some(cid) } else { None })
        .collect();
    if !chunk_ids.is_empty() {
        let mut completed = 0usize;
        for cid in &chunk_ids {
            if let Some(chunk) = snapshot.active_tasks.get(*cid) {
                if let TaskStatus::Failed { error } = &chunk.status {
                    return Json(TaskStatusResponse {
                        task_id,
                        status: "failed".to_string(),
                        message: format!("Chunk {cid} failed: {error}"),
                    });
                }
            }
            if snapshot.results.contains_key(*cid) {
                completed += 1;
            }
        }
        if completed == chunk_ids.len() {
            return Json(TaskStatusResponse {
                task_id,
                status: "completed".to_string(),
                message: format!("All {} chunks completed", chunk_ids.len()),
            });
        }
        return Json(TaskStatusResponse {
            task_id,
            status: "processing".to_string(),
            message: format!("{completed}/{} chunks completed", chunk_ids.len()),
        });
    }

    Json(TaskStatusResponse {
        task_id,
        status: "not_found".to_string(),
        message: "Task not found".to_string(),
    })
}

pub fn create_api_router(coordinator: Arc<Coordinator>) -> Router {
    let state = ApiState { coordinator };

    Router::new()
        .route("/api/tasks/submit", post(submit_task))
        .route("/api/tasks/:task_id", get(get_task_status))
        .layer(Extension(state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_submit_request_checks_type_bounds_and_algorithm() {
        let valid = SubmitTaskRequest {
            task_type: "hash".to_string(),
            start: 0,
            end: 100,
            algorithm: "SHA256".to_string(),
        };
        assert!(validate_submit_request(&valid).is_ok());

        let bad_type = SubmitTaskRequest {
            task_type: "unknown".to_string(),
            ..valid.clone()
        };
        assert_eq!(
            validate_submit_request(&bad_type).unwrap_err(),
            StatusCode::BAD_REQUEST
        );

        let bad_range = SubmitTaskRequest {
            start: 100,
            end: 100,
            ..valid.clone()
        };
        assert_eq!(
            validate_submit_request(&bad_range).unwrap_err(),
            StatusCode::BAD_REQUEST
        );

        let bad_algo = SubmitTaskRequest {
            algorithm: "md5".to_string(),
            ..valid
        };
        assert_eq!(
            validate_submit_request(&bad_algo).unwrap_err(),
            StatusCode::BAD_REQUEST
        );
    }
}
