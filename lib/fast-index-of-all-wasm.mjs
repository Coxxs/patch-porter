import { createIndex, freeIndex, indexOfAll as wasmIndexOfAll } from 'fast-index-of-all'

const cache = new WeakMap()
const registry = new FinalizationRegistry((handle) => {
  freeIndex(handle)
})

/**
 * @param {Uint8Array} buffer Buffer to search
 * @param {Uint8Array} search Buffer to search for
 * @returns {Promise<Array<number>>} Array of indexes
 */
export async function indexOfAll(buffer, search, start = 0, end = null, maxCount = null) {
  let handle = cache.get(buffer)
  if (!handle) {
    console.log('Generating cache...')
    handle = await createIndex(buffer)
    cache.set(buffer, handle)
    registry.register(buffer, handle)
  }

  return wasmIndexOfAll(handle, search, start, end, maxCount).sort()
}