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

    let task_type = TaskType::HashCalculation {
        start: req.start,
        end: req.end,
        algorithm: req.algorithm,
    };

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
    Extension(_state): Extension<ApiState>,
) -> Json<TaskStatusResponse> {
    log::info!("API: Task status request: {}", task_id);

    // For now, return a simple response
    Json(TaskStatusResponse {
        task_id: task_id.clone(),
        status: "processing".to_string(),
        message: "Task is being processed".to_string(),
    })
}

pub fn create_api_router(coordinator: Arc<Coordinator>) -> Router {
    let state = ApiState { coordinator };

    Router::new()
        .route("/api/tasks/submit", post(submit_task))
        .route("/api/tasks/:task_id", get(get_task_status))
        .layer(Extension(state))
}
