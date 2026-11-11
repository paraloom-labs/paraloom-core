/**
 * Swap outputs management and persistence layer with synchronization.
 */
import { storage } from '../storage/secure';

export interface SwapOutput {
  id: string;
  status: 'pending' | 'completed' | 'dismissed' | 'failed';
  amount: string;
  token: string;
  timestamp: number;
  txHash?: string;
}

let writeLock = Promise.resolve();

async function withWriteLock<T>(fn: () => Promise<T>): Promise<T> {
  let unlock: () => void = () => {};
  const nextLock = new Promise<void>((resolve) => {
    unlock = resolve;
  });
  const currentLock = writeLock;
  writeLock = nextLock;
  await currentLock;
  try {
    return await fn();
  } finally {
    unlock();
  }
}

export async function getSwapOutputs(): Promise<SwapOutput[]> {
  const data = await storage.get('paraloom_swap_outputs');
  if (!data || !Array.isArray(data)) {
    return [];
  }
  return data as SwapOutput[];
}

export async function saveSwapOutput(output: SwapOutput): Promise<SwapOutput[]> {
  return withWriteLock(async () => {
    const outputs = await getSwapOutputs();
    const index = outputs.findIndex((o) => o.id === output.id);
    
    let updated: SwapOutput[];
    if (index >= 0) {
      updated = [
        ...outputs.slice(0, index),
        { ...outputs[index], ...output, timestamp: outputs[index].timestamp },
        ...outputs.slice(index + 1),
      ];
    } else {
      updated = [output, ...outputs];
    }
    
    await storage.set('paraloom_swap_outputs', updated);
    return updated;
  });
}

export async function dismissSwapOutput(id: string): Promise<SwapOutput[]> {
  return withWriteLock(async () => {
    const outputs = await getSwapOutputs();
    const updated = outputs.map((o) => (o.id === id ? { ...o, status: 'dismissed' as const } : o));
    await storage.set('paraloom_swap_outputs', updated);
    return updated;
  });
}
