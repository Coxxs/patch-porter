import { createIndex, freeIndex, indexOfAll as wasmIndexOfAll } from 'fast-index-of-all'

const cache = new WeakMap()
const registry = new FinalizationRegistry(async (handle) => {
  try {
    freeIndex(await handle)
  } catch (err) {
    // Ignore errors during finalization (e.g. if creation failed)
  }
})

export async function prepareIndex(buffer) {
  let handle = cache.get(buffer)
  if (!handle) {
    console.log('Generating cache...')
    handle = createIndex(buffer)
    
    // If creation fails, remove from cache so we can try again
    handle.catch(() => cache.delete(buffer))
    
    cache.set(buffer, handle)
    registry.register(buffer, handle)
  }
  return handle
}

/**
 * @param {Uint8Array} buffer Buffer to search
 * @param {Uint8Array} search Buffer to search for
 * @returns {Promise<Array<number>>} Array of indexes
 */
export async function indexOfAll(buffer, search, start = 0, end = null, maxCount = null) {
  let handle = await prepareIndex(buffer)
  return wasmIndexOfAll(handle, search, start, end, maxCount).sort((a, b) => a - b)
}