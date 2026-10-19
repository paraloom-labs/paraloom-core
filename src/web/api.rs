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
use crate::task::{TaskId, TaskType};

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

async fn submit_task(
    Extension(state): Extension<ApiState>,
    Json(req): Json<SubmitTaskRequest>,
) -> Result<Json<SubmitTaskResponse>, StatusCode> {
    log::info!("API: Received task submission request: {:?}", req);

    if !matches!(
        req.task_type.trim().to_ascii_lowercase().as_str(),
        "hash_calculation" | "hashcalculation" | "hash"
    ) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let task_type = TaskType::HashCalculation {
        start: req.start,
        end: req.end,
        algorithm: req.algorithm,
    };

    if crate::task::Task::new(task_type.clone()).validate().is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }

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
) -> Result<Json<TaskStatusResponse>, StatusCode> {
    log::info!("API: Task status request: {}", task_id);

    let (status, message) = state
        .coordinator
        .get_task_status(&task_id)
        .await
        .ok_or(StatusCode::NOT_FOUND)?;

    Ok(Json(TaskStatusResponse {
        task_id,
        status,
        message,
    }))
}

pub fn create_api_router(coordinator: Arc<Coordinator>) -> Router {
    let state = ApiState { coordinator };

    Router::new()
        .route("/api/tasks/submit", post(submit_task))
        .route("/api/tasks/:task_id", get(get_task_status))
        .layer(Extension(state))
}
