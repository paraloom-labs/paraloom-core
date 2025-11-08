// Test for coordinator task distribution logic

#[test]
fn test_task_chunk_distribution() {
    // Test case 1: Even distribution
    let total_range = 100u64;
    let num_validators = 4;
    let chunk_size = total_range.div_ceil(num_validators);

    assert_eq!(chunk_size, 25);

    // Test case 2: Uneven distribution
    let total_range = 100u64;
    let num_validators = 3;
    let chunk_size = total_range.div_ceil(num_validators);

    assert_eq!(chunk_size, 34); // ceil(100/3) = 34

    // Test case 3: More validators than tasks
    let total_range = 5u64;
    let num_validators = 10;
    let chunk_size = total_range.div_ceil(num_validators);

    assert_eq!(chunk_size, 1);
}

#[test]
fn test_chunk_boundaries() {
    // Simulate chunk creation logic
    let start = 1u64;
    let end = 100u64;
    let num_validators = 4;
    let total = end - start + 1;
    let chunk_size = total.div_ceil(num_validators as u64);

    let mut chunks = Vec::new();
    let mut current_start = start;

    for _ in 0..num_validators {
        let chunk_end = (current_start + chunk_size - 1).min(end);
        chunks.push((current_start, chunk_end));
        current_start = chunk_end + 1;
        if current_start > end {
            break;
        }
    }

    // Verify we created chunks
    assert!(!chunks.is_empty());

    // Verify first chunk starts at beginning
    assert_eq!(chunks[0].0, start);

    // Verify last chunk ends at end
    assert_eq!(chunks.last().unwrap().1, end);

    // Verify no gaps between chunks
    for i in 0..chunks.len() - 1 {
        assert_eq!(chunks[i].1 + 1, chunks[i + 1].0);
    }

    // Verify total coverage
    let total_covered: u64 = chunks.iter().map(|(s, e)| e - s + 1).sum();
    assert_eq!(total_covered, total);
}

#[test]
fn test_single_validator() {
    // When there's only one validator, it should get the entire range
    let start = 1u64;
    let end = 1000u64;
    let num_validators = 1;
    let total = end - start + 1;
    let chunk_size = total.div_ceil(num_validators as u64);

    assert_eq!(chunk_size, 1000);
}

#[test]
fn test_edge_case_small_range() {
    // Test with a very small range
    let start = 1u64;
    let end = 1u64;
    let num_validators = 5;
    let total = end - start + 1;
    let chunk_size = total.div_ceil(num_validators as u64);

    // Should still have a chunk size of 1
    assert_eq!(chunk_size, 1);
}
