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

const INDEX_MAP_MAX_LENGTH = 600000
const INDEX_MAP_KEY_BITSIZE = 20
const INDEX_MAP_KEY_BYTESIZE = Math.ceil(INDEX_MAP_KEY_BITSIZE / 8)
const INDEX_MAP_KEY_MAP_SIZE = 1 << INDEX_MAP_KEY_BITSIZE
const INDEX_MAP_KEY_FUNC = (buffer, i) => ((buffer[i] << 12) + (buffer[i + 1] << 4) + (buffer[i + 2] >> 4))

function generateIndexMapFast(buffer) {
  const count = new Uint32Array(INDEX_MAP_KEY_MAP_SIZE)
  for (let i = 0; i <= buffer.length - INDEX_MAP_KEY_BYTESIZE; i++) {
    const prefix = INDEX_MAP_KEY_FUNC(buffer, i)
    count[prefix]++
  }

  const result = new Array(INDEX_MAP_KEY_MAP_SIZE)
  for (let i = 0; i < INDEX_MAP_KEY_MAP_SIZE; i++) {
    result[i] = count[i] > INDEX_MAP_MAX_LENGTH ? false : new Uint32Array(count[i])
  }

  const counter = new Uint32Array(INDEX_MAP_KEY_MAP_SIZE)
  for (let i = 0; i <= buffer.length - INDEX_MAP_KEY_BYTESIZE; i++) {
    const prefix = INDEX_MAP_KEY_FUNC(buffer, i)
    if (result[prefix] === false) continue
    result[prefix][counter[prefix]] = i
    counter[prefix]++
  }
  return result
}

function generateIndexMap(buffer) {
  const result = Array.from(new Array(INDEX_MAP_KEY_MAP_SIZE), () => new Array())
  for (let i = 0; i <= buffer.length - INDEX_MAP_KEY_BYTESIZE; i++) {
    const prefix = INDEX_MAP_KEY_FUNC(buffer, i)
    if (result[prefix] === false) continue
    result[prefix].push(i)
    if (result[prefix].length > INDEX_MAP_MAX_LENGTH) {
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
  if (buffer.length < 0x1000000 || search.length < INDEX_MAP_KEY_BYTESIZE) return indexOfAllSlow(buffer, search, start, end, maxCount)
  let cache = caches.get(buffer)
  if (!cache) {
    console.log('Generating cache...')
    cache = generateIndexMapFast(buffer)
    caches.set(buffer, cache)
  }
  let prefix = INDEX_MAP_KEY_FUNC(search, 0)
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