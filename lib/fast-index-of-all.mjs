/**
 * @param {Uint8Array} buffer Buffer to search
 * @param {Uint8Array} search Buffer to search for
 * @returns {Array<number>} Array of indexes
 */
function indexOfAllSlow(buffer, search, start, end, maxCount) {
buffer = Buffer.from(buffer)
  search = Buffer.from(search)
  const result = []
  let offset = 0
  if (start != null && end != null) {
    buffer = buffer.subarray(start, end)
  }
if (start == null) {
    start = 0
  }
  if (end == null) {
    end = buffer.length
  }
  while (true) {
    const index = buffer.indexOf(search, offset)
    if (index === -1) break
    result.push(index + start)
    offset = index + 1
    if (maxCount && result.length >= maxCount) break
  }
  return result
}

const MAX_INDEX_MAP_LENGTH = 600000

function generateIndexMap(buffer) {
  const result = Array.from(new Array(0x100000), () => new Array())
  for (let i = 0; i < buffer.length - 2; i++) {
    const prefix = (buffer[i] << 12) + (buffer[i + 1] << 4) + (buffer[i + 2] >> 4)
    if (result[prefix] === false) continue
    result[prefix].push(i)
    if (result[prefix].length > MAX_INDEX_MAP_LENGTH) {
      result[prefix] = false
      continue
    }
  }
  return result
}

const caches = new WeakMap()

/**
 * @param {Uint8Array} buffer Buffer to search
 * @param {Uint8Array} search Buffer to search for
 * @returns {Array<number>} Array of indexes
 */
export function indexOfAll(buffer, search, start, end, maxCount = null) {
  if (buffer.length < 0x1000000 || search.length < 3) return indexOfAllSlow(buffer, search, start, end, maxCount)
  let cache = caches.get(buffer)
  if (!cache) {
    console.log('Generating cache...')
    cache = generateIndexMap(buffer)
    caches.set(buffer, cache)
  }
  let prefix = (search[0] << 12) + (search[1] << 4) + (search[2] >> 4)
  const result = []
  // console.log(`Searching for ${prefix}... ${cache[prefix].length}`)
  if (cache[prefix] === false) return indexOfAllSlow(buffer, search, start, end, maxCount)
  for (const index of cache[prefix]) {
    if (index < start || index + search.length > end) continue
    let found = true
    for (let i = search.length - 1; i >= 0; i--) {
      if (buffer[index + i] !== search[i]) {
        found = false
        break
      }
    }
    if (!found) continue
    result.push(index)
    if (maxCount && result.length >= maxCount) break
  }
  return result
}