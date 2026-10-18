// Integration tests for Coordinator::split_task chunk distribution logic

use paraloom::config::Settings;
use paraloom::coordinator::Coordinator;
use paraloom::network::NetworkManager;
use paraloom::task::{Task, TaskType};
use paraloom::types::NodeId;
use std::sync::Arc;

async fn coordinator_with_validators(count: usize) -> Coordinator {
    let network = Arc::new(NetworkManager::new(&Settings::development()).expect("test network"));
    let coordinator = Coordinator::new(network);
    for i in 0..count {
        coordinator
            .register_validator(NodeId(vec![(i + 1) as u8]))
            .await;
    }
    coordinator
}

fn chunk_ranges(chunks: &[Task]) -> Vec<(u64, u64)> {
    chunks
        .iter()
        .map(|chunk| match &chunk.task_type {
            TaskType::HashCalculation { start, end, .. } => (*start, *end),
        })
        .collect()
}

#[tokio::test]
async fn test_task_chunk_distribution() {
    // Case 1: Even distribution (1..=100 across 4 validators -> 4 chunks of 25)
    let coord_even = coordinator_with_validators(4).await;
    let task_100 = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 100,
        algorithm: "sha256".to_string(),
    });
    let chunks_even = coord_even.split_task(&task_100).await.unwrap();
    assert_eq!(
        chunk_ranges(&chunks_even),
        vec![(1, 25), (26, 50), (51, 75), (76, 100)]
    );

    // Case 2: Uneven distribution (1..=100 across 3 validators -> 34, 34, 32)
    let coord_uneven = coordinator_with_validators(3).await;
    let chunks_uneven = coord_uneven.split_task(&task_100).await.unwrap();
    assert_eq!(
        chunk_ranges(&chunks_uneven),
        vec![(1, 34), (35, 68), (69, 100)]
    );

    // Case 3: More validators than tasks (1..=5 across 10 validators -> 5 chunks of 1)
    let coord_many = coordinator_with_validators(10).await;
    let task_5 = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 5,
        algorithm: "sha256".to_string(),
    });
    let chunks_many = coord_many.split_task(&task_5).await.unwrap();
    assert_eq!(
        chunk_ranges(&chunks_many),
        vec![(1, 1), (2, 2), (3, 3), (4, 4), (5, 5)]
    );
}

#[tokio::test]
async fn test_chunk_boundaries() {
    let start = 1u64;
    let end = 100u64;
    let total = end - start + 1;

    let coordinator = coordinator_with_validators(4).await;
    let task = Task::new(TaskType::HashCalculation {
        start,
        end,
        algorithm: "sha256".to_string(),
    });

    let chunks = coordinator.split_task(&task).await.unwrap();
    let ranges = chunk_ranges(&chunks);

    assert_eq!(ranges.len(), 4);
    assert_eq!(ranges[0].0, start);
    assert_eq!(ranges.last().unwrap().1, end);

    // Verify chunk IDs and contiguous non-overlapping coverage
    for (i, chunk) in chunks.iter().enumerate() {
        assert_eq!(chunk.id, format!("{}-chunk-{}", task.id, i));
    }
    for i in 0..ranges.len() - 1 {
        assert_eq!(ranges[i].1 + 1, ranges[i + 1].0);
    }

    let total_covered: u64 = ranges.iter().map(|(s, e)| e - s + 1).sum();
    assert_eq!(total_covered, total);
}

#[tokio::test]
async fn test_single_validator() {
    // When there is only one validator, it must receive the entire range in a single chunk
    let coordinator = coordinator_with_validators(1).await;
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 1000,
        algorithm: "sha256".to_string(),
    });

    let chunks = coordinator.split_task(&task).await.unwrap();
    assert_eq!(chunk_ranges(&chunks), vec![(1, 1000)]);
}

#[tokio::test]
async fn test_empty_validators_guard() {
    // When no validators are registered yet, `validators.len().max(1)` must guard
    // against `div_ceil(0)` and produce a single chunk covering the entire range.
    let coordinator = coordinator_with_validators(0).await;
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 1000,
        algorithm: "sha256".to_string(),
    });

    let chunks = coordinator.split_task(&task).await.unwrap();
    assert_eq!(chunk_ranges(&chunks), vec![(1, 1000)]);
}

#[tokio::test]
async fn test_edge_case_small_range() {
    // Single-element range (1..=1) with 5 validators must emit only 1 chunk (1, 1)
    // and skip the remaining 4 iterations where `current_start > end`.
    let coordinator = coordinator_with_validators(5).await;
    let task = Task::new(TaskType::HashCalculation {
        start: 1,
        end: 1,
        algorithm: "sha256".to_string(),
    });

    let chunks = coordinator.split_task(&task).await.unwrap();
    assert_eq!(chunk_ranges(&chunks), vec![(1, 1)]);
}
