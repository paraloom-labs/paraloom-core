use paraloom::storage::BlockchainStorage;
use paraloom::task::{Task, TaskType};
use tempfile::TempDir;

#[test]
fn test_task_storage_roundtrip() {
    // Create temporary directory for test database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");

    // Open storage
    let storage = BlockchainStorage::open(&db_path).unwrap();

    // Create a test task
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 100,
        algorithm: "sha256".to_string(),
    });

    let task_id = task.id.clone();

    // Serialize and store task
    let serialized = bincode::serialize(&task).unwrap();
    let key = format!("task:{}", task_id);
    storage.put(key.as_bytes(), &serialized).unwrap();

    // Retrieve and deserialize
    let retrieved = storage.get(key.as_bytes()).unwrap();
    assert!(retrieved.is_some(), "Task should exist in storage");

    let deserialized: Task = bincode::deserialize(&retrieved.unwrap()).unwrap();

    // Verify roundtrip
    assert_eq!(deserialized.id, task_id);
    assert_eq!(deserialized.status, task.status);

    match (&deserialized.task_type, &task.task_type) {
        (
            TaskType::HashCalculation {
                start: s1,
                end: e1,
                algorithm: a1,
            },
            TaskType::HashCalculation {
                start: s2,
                end: e2,
                algorithm: a2,
            },
        ) => {
            assert_eq!(s1, s2);
            assert_eq!(e1, e2);
            assert_eq!(a1, a2);
        }
    }
}

#[test]
fn test_storage_delete() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = BlockchainStorage::open(&db_path).unwrap();

    let key = b"test_key";
    let value = b"test_value";

    // Put and verify
    storage.put(key, value).unwrap();
    assert!(storage.get(key).unwrap().is_some());

    // Delete and verify
    storage.delete(key).unwrap();
    assert!(storage.get(key).unwrap().is_none());
}

#[test]
fn test_storage_flush() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let storage = BlockchainStorage::open(&db_path).unwrap();

    storage.put(b"key", b"value").unwrap();
    storage.flush().unwrap();

    // Verify data persists
    assert!(storage.get(b"key").unwrap().is_some());
}
