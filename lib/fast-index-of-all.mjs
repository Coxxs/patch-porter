/**
 * @param {Buffer} buffer Buffer to search
 * @param {Buffer} search Buffer to search for
 * @returns {Array<number>} Array of indexes
 */
function indexOfAllSlow(buffer, search, start, end, maxCount) {
  const result = []
  let offset = 0
  if (start != null && end != null) {
    buffer = buffer.subarray(start, end)
  }
  while (true) {
    const index = buffer.indexOf(search, offset)
    if (index === -1) break
    result.push(index)
    offset = index + 1
    if (maxCount && result.length >= maxCount) break
  }
  return result
}

function generateIndexMap(buffer) {
  const result = Array.from(new Array(0x10000), () => new Array())
  for (let i = 0; i < buffer.length - 1; i++) {
    const int = buffer.readUInt16LE(i)
    result[int].push(i)
  }
  return result
}

const caches = new WeakMap()

/**
 * @param {Buffer} buffer Buffer to search
 * @param {Buffer} search Buffer to search for
 * @returns {Array<number>} Array of indexes
 */
export function indexOfAll(buffer, search, start, end, maxCount = null) {
  if (buffer.length < 0x1000000 || search.length < 2) return indexOfAllSlow(buffer, search, start, end, maxCount)
  let cache = caches.get(buffer)
  if (!cache) {
    console.log('Generating cache...')
    cache = generateIndexMap(buffer)
    caches.set(buffer, cache)
  }
  let short = search.readUInt16LE(0)
  const result = []
  // console.log(`Searching for ${short}... ${cache[short].length}`)
  if (cache[short].length > 500000) return indexOfAllSlow(buffer, search, start, end, maxCount)
  for (const index of cache[short]) {
    if (index < start || index + search.length > end) continue
    if (buffer.subarray(index, index + search.length).equals(search)) {
      result.push(index)
      if (maxCount && result.length >= maxCount) break
    }
  }
  return result
}