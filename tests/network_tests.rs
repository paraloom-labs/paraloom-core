use paraloom::network::{Message, ResultRequest, ResultResponse};
use paraloom::task::{ResultData, Task, TaskResult, TaskType};
use paraloom::types::{NodeId, NodeInfo, NodeType, ResourceContribution};

#[test]
fn test_message_serialization() {
    // Test Ping/Pong
    let ping = Message::Ping;
    let serialized = bincode::serialize(&ping).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();
    assert!(matches!(deserialized, Message::Ping));

    let pong = Message::Pong;
    let serialized = bincode::serialize(&pong).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();
    assert!(matches!(deserialized, Message::Pong));
}

#[test]
fn test_task_request_message() {
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 100,
        algorithm: "sha256".to_string(),
    });

    let message = Message::TaskRequest {
        task: task.clone(),
        coordinator_id: NodeId(b"coordinator-1".to_vec()),
    };

    // Serialize and deserialize
    let serialized = bincode::serialize(&message).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();

    match deserialized {
        Message::TaskRequest {
            task: t,
            coordinator_id,
        } => {
            assert_eq!(t.id, task.id);
            assert_eq!(coordinator_id, NodeId(b"coordinator-1".to_vec()));
        }
        _ => panic!("Expected TaskRequest"),
    }
}

#[test]
fn test_task_response_message() {
    let result = TaskResult {
        task_id: "task-123".to_string(),
        execution_time_ms: 1000,
        data: ResultData::Hashes {
            hashes: vec![(1, "abc".to_string())],
            count: 1,
        },
    };

    let message = Message::TaskResponse {
        result: result.clone(),
    };

    // Serialize and deserialize
    let serialized = bincode::serialize(&message).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();

    match deserialized {
        Message::TaskResponse { result: r } => {
            assert_eq!(r.task_id, result.task_id);
            assert_eq!(r.execution_time_ms, result.execution_time_ms);
        }
        _ => panic!("Expected TaskResponse"),
    }
}

#[test]
fn test_result_request_response() {
    // Test ResultRequest
    let task_result = TaskResult {
        task_id: "test-task".to_string(),
        execution_time_ms: 500,
        data: ResultData::Hashes {
            hashes: vec![],
            count: 0,
        },
    };

    let request = ResultRequest {
        result: task_result.clone(),
    };

    let serialized = bincode::serialize(&request).unwrap();
    let deserialized: ResultRequest = bincode::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.result.task_id, task_result.task_id);

    // Test ResultResponse
    let response = ResultResponse {
        success: true,
        message: "Task received".to_string(),
    };

    let serialized = bincode::serialize(&response).unwrap();
    let deserialized: ResultResponse = bincode::deserialize(&serialized).unwrap();
    assert!(deserialized.success);
    assert_eq!(deserialized.message, "Task received");
}

#[test]
fn test_discovery_message() {
    let node_info = NodeInfo {
        id: NodeId(b"node-1".to_vec()),
        node_type: NodeType::ResourceProvider,
        address: "/ip4/127.0.0.1/tcp/0".to_string(),
        resources: ResourceContribution {
            cpu_cores: 4,
            memory_mb: 8192,
            storage_mb: 10000,
            bandwidth_kbps: 1000,
        },
    };

    let message = Message::Discovery {
        node_info: node_info.clone(),
    };

    let serialized = bincode::serialize(&message).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();

    match deserialized {
        Message::Discovery { node_info: info } => {
            assert_eq!(info.id, node_info.id);
            assert_eq!(info.resources.cpu_cores, 4);
        }
        _ => panic!("Expected Discovery"),
    }
}

#[test]
fn test_task_error_message() {
    let message = Message::TaskError {
        task_id: "failed-task".to_string(),
        error: "Out of memory".to_string(),
    };

    let serialized = bincode::serialize(&message).unwrap();
    let deserialized: Message = bincode::deserialize(&serialized).unwrap();

    match deserialized {
        Message::TaskError { task_id, error } => {
            assert_eq!(task_id, "failed-task");
            assert_eq!(error, "Out of memory");
        }
        _ => panic!("Expected TaskError"),
    }
}
