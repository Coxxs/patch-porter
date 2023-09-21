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
    result.push(index + start)
    offset = index + 1
    if (maxCount && result.length >= maxCount) break
  }
  return result
}

const MAX_INDEX_MAP_LENGTH = 600000

function generateIndexMap(buffer) {
  const result = Array.from(new Array(0x10000), () => new Array())
  for (let i = 0; i < buffer.length - 1; i++) {
    const int = buffer.readUInt16LE(i)
    if (result[int] === false) continue
    result[int].push(i)
    if (result[int].length > MAX_INDEX_MAP_LENGTH) {
      result[int] = false
      continue
    }
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
  if (cache[short] === false) return indexOfAllSlow(buffer, search, start, end, maxCount)
  for (const index of cache[short]) {
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