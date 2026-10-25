import { describe, it, expect } from 'vitest';
import { safeDataProcessor } from './instructions';

describe('paraloom-labs/paraloom-core - Issue #1220', () => {
  it('should gracefully handle null or malformed data without throwing', () => {
    const result = safeDataProcessor(null, { fallback: { status: 'safe' } });
    expect(result).toEqual({ status: 'safe' });
  });

  it('should process valid data cleanly', () => {
    const input = { id: 101, title: 'Test Entry' };
    const result = safeDataProcessor(input);
    expect(result.isProcessed).toBe(true);
  });
});
