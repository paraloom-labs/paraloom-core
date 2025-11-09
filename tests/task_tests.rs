use paraloom::task::{ResultData, Task, TaskResult, TaskStatus, TaskType};

#[test]
fn test_task_serialization() {
    // Create a task
    let task = Task::new(TaskType::HashCalculation {
        start: 1000,
        end: 2000,
        algorithm: "sha256".to_string(),
    });

    // Serialize
    let serialized = bincode::serialize(&task).unwrap();
    assert!(!serialized.is_empty());

    // Deserialize
    let deserialized: Task = bincode::deserialize(&serialized).unwrap();

    // Verify
    assert_eq!(task.id, deserialized.id);
    assert_eq!(task.status, deserialized.status);
    assert_eq!(task.created_at, deserialized.created_at);
}

#[test]
fn test_task_result_serialization() {
    // Create a result
    let result = TaskResult {
        task_id: "test-task-123".to_string(),
        execution_time_ms: 500,
        data: ResultData::Hashes {
            hashes: vec![(1, "hash1".to_string()), (2, "hash2".to_string())],
            count: 2,
        },
    };

    // Serialize
    let serialized = bincode::serialize(&result).unwrap();
    assert!(!serialized.is_empty());

    // Deserialize
    let deserialized: TaskResult = bincode::deserialize(&serialized).unwrap();

    // Verify
    assert_eq!(result.task_id, deserialized.task_id);
    assert_eq!(result.execution_time_ms, deserialized.execution_time_ms);

    match (&result.data, &deserialized.data) {
        (
            ResultData::Hashes {
                hashes: h1,
                count: c1,
            },
            ResultData::Hashes {
                hashes: h2,
                count: c2,
            },
        ) => {
            assert_eq!(c1, c2);
            assert_eq!(h1.len(), h2.len());
            assert_eq!(h1, h2);
        }
    }
}

#[test]
fn test_task_status_equality() {
    assert_eq!(TaskStatus::Pending, TaskStatus::Pending);
    assert_eq!(TaskStatus::Running, TaskStatus::Running);
    assert_eq!(TaskStatus::Completed, TaskStatus::Completed);

    assert_ne!(TaskStatus::Pending, TaskStatus::Running);
}

#[test]
fn test_task_creation() {
    let task = Task::new(TaskType::HashCalculation {
        start: 0,
        end: 100,
        algorithm: "sha256".to_string(),
    });

    // Verify default values
    assert!(!task.id.is_empty());
    assert_eq!(task.status, TaskStatus::Pending);
    assert!(task.assigned_to.is_none());
    assert!(task.created_at > 0);
}

#[test]
fn test_json_serialization() {
    // Test JSON serialization for API compatibility
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 10,
        algorithm: "sha256".to_string(),
    });

    // Serialize to JSON
    let json = serde_json::to_string(&task).unwrap();
    assert!(!json.is_empty());

    // Deserialize from JSON
    let deserialized: Task = serde_json::from_str(&json).unwrap();
    assert_eq!(task.id, deserialized.id);
}
