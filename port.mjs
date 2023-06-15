import { indexOfAll } from "./lib/fast-index-of-all.mjs"
function dec2hex(number, length) {
  return number.toString(16).padStart(length, '0').toUpperCase()
}

const searchModesGlobal = [
  { start: 64, end: -64, length: 12, step: -4, range: null },
  { start: 64, end: -64, length: 16, step: -4, range: null },
  { start: 256, end: -256, length: 16, step: -4, range: null },
  { start: 1024, end: -1024, length: 16, step: -4, range: null },
]

const searchModesDefault = [
  { start: 16, end: -16, length: 12, step: -4, range: 0x200000 },
  { start: 16, end: -16, length: 16, step: -4, range: 0x200000 },
  { start: 16, end: -16, length: 20, step: -4, range: 0x200000 },

  { start: 16, end: -16, length: 12, step: -4, range: 0x400000 },
  { start: 16, end: -16, length: 16, step: -4, range: 0x400000 },
  { start: 16, end: -16, length: 20, step: -4, range: 0x400000 },

  { start: 32, end: -32, length: 12, step: -4, range: 0x400000 },
  { start: 32, end: -32, length: 16, step: -4, range: 0x400000 },
  { start: 32, end: -32, length: 20, step: -4, range: 0x400000 },

  // { start: 32, end: -32, length: 8, step: -4, range: null },
  { start: 48, end: -48, length: 12, step: -4, range: null },
  { start: 48, end: -48, length: 16, step: -4, range: null },
  { start: 48, end: -48, length: 20, step: -4, range: null },
]

const searchModesFast = [
  { start: 16, end: -16, length: 12, step: -4, range: 0x100 },
  { start: 24, end: -24, length: 16, step: -4, range: 0x200 },
  { start: 64, end: -64, length: 16, step: -4, range: 0x1000 },
]

/**
 * @param {Buffer} buffer NSO file
 * @returns {string} nsobid
 */
function getNsobid(buffer) {
  let nsobid = buffer.subarray(0x40, 0x40 + 0x20).toString('hex').toUpperCase()
  nsobid = nsobid.replace(/(00)*$/, '')
  return nsobid
}

/**
 * @param {Buffer} fileOld
 * @param {Buffer} fileNew
 * @param {number} address 
 * @param {object} searchMode
 * @returns {Array<object> | false} results
 */
export function portAddressSearchMode(fileOld, fileNew, address, offset = 0, searchMode = searchModesDefault[0]) {
  if (!Number.isInteger(address)) {
    throw new Error('address must be an integer')
  }
  const { start, end, length, step, range } = searchMode
  if (start == end && step <= 0) {
    step = 1 // prevent infinite loop
  }
  if (start > end && step > 0 || start < end && step < 0) {
    throw new Error(`Search mode ${JSON.stringify(searchMode)} will cause an infinite loop`)
  }
  // limit search range
  let startOffset
  let endOffset
  // let searchOld
  // let searchNew
  if (Number.isInteger(range)) {
    startOffset = Math.max(0, address + offset - range)
    endOffset = address + offset + range
    // searchOld = fileOld.subarray(startOffset, address + offset + range)
    // searchNew = fileNew.subarray(startOffset, address + offset + range)
  } else {
    startOffset = 0
    endOffset = fileNew.length
    // searchOld = fileOld
    // searchNew = fileNew
  }
  let results = []
  for (let i = start; start > end ? i >= end : i <= end ; i += step) {
    const ptr = address + i
    const data = fileOld.subarray(ptr, ptr + length)
    const indexs = indexOfAll(fileNew, data, startOffset, endOffset, 2)
    if (indexs.length == 0) continue
    if (indexs.length > 1) continue
    const index = indexs[0]
    let delta = index - ptr
    results.push({ old: ptr, new: ptr + delta, delta: delta })
  }
  // console.log(`Found with mode ${JSON.stringify(searchMode)}, results ${JSON.stringify(results)}`)
  return results
}

/**
 * @param {Buffer} fileOld
 * @param {Buffer} fileNew
 * @param {number} address
 * @param {object} searchMode
 * @returns {number | false} offset
 */
export function getEstimatedOffset(fileOld, fileNew, address, searchMode = searchModesGlobal[0]) {
  const results = portAddressSearchMode(fileOld, fileNew, address, 0, searchMode)
  // console.log(`Estimating offset with search mode ${JSON.stringify(searchMode)}, results ${JSON.stringify(results)}`)
  if (results.length == 0) return false

  const deltas = results.map(result => result.delta)
  deltas.sort((a, b) => a - b)
  const median = deltas[Math.floor(deltas.length / 2)]

  if (deltas.filter(delta => delta > median - 0x20 && delta < median + 0x20).length >= 3) {
    return median
  }
  return false
}

/**
 * @param {Buffer} fileOld
 * @param {Buffer} fileNew
 * @param {number} address 
 * @param {Array<object>} searchModes
 * @returns {number | false} address
 */
export function portAddress(fileOld, fileNew, address, searchModesOffset = searchModesGlobal, searchModes = searchModesFast) {
  if (!Number.isInteger(address)) {
    throw new Error('address must be an integer')
  }
  let estimatedOffset
  if (searchModesOffset) {
    for (const searchMode of searchModesOffset) {
      estimatedOffset = getEstimatedOffset(fileOld, fileNew, address, searchMode)
      if (estimatedOffset !== false) break
    }
    // console.log(`Estimated offset: ${estimatedOffset}`)
    if (estimatedOffset === false) return false  
  } else {
    estimatedOffset = 0
  }

  let results = []
  for (const searchMode of searchModes) {
    const searchResults = portAddressSearchMode(fileOld, fileNew, address, estimatedOffset, searchMode)
    // console.log(`Search mode ${JSON.stringify(searchMode)}, results ${JSON.stringify(results)}`)
    if (searchResults.length == 0) continue
    const deltas = searchResults.map(r => r.delta)
    deltas.sort((a, b) => a - b)
    const median = deltas[Math.floor(deltas.length / 2)]
    const count = deltas.filter(delta => delta == median).length
    if (count >= 2 && count > deltas.length * 0.3) {
      results.push({ old: address, new: address + median, delta: median, confidence: 1 })
      break
    } else if (deltas.length == 1) {
      results.push({ old: address, new: address + median, delta: median, confidence: 0.5 })
    }
  }
  if (searchModesOffset) {
    results.push({ old: address, new: address + estimatedOffset, delta: estimatedOffset, confidence: 0.1 })
  }
  results = results.sort((a, b) => b.confidence - a.confidence)
  return results.length > 0 ? results[0] : false
}

/**
 * @param {Buffer} fileOld 
 * @param {Buffer} fileNew 
 * @param {string} pchtxt 
 * @param {object} options 
 * @returns {Promise<string>} pchtxt
 */
export async function portPchtxt(fileOld, fileNew, pchtxt, options) {
  options = {
    addComment: false,
    ...options,
  }
  const lines = pchtxt.replaceAll('\r\n', '\n').split('\n')
  const output = []

  let offset = 0
  for (const line of lines) {
    let match
    if (match = line.match(/^@nsobid-(?<nsobid>[0-9a-fA-F]+)\s*$/)) {
      let pchtxtNsobid = match.groups.nsobid.toUpperCase()
      let oldNsobid = getNsobid(fileOld)
      let newNsobid = getNsobid(fileNew)
      if (oldNsobid !== pchtxtNsobid) {
        throw new Error(`nsobid mismatch: ${oldNsobid} (nso) != ${pchtxtNsobid} (pchtxt)`)
      }
      output.push(`@nsobid-${newNsobid}`)
      continue
    }

    if (match = line.match(/^@flag\s+offset_shift\s+0x(?<offset>[0-9a-fA-F]+)\s*$/)) {
      offset = parseInt(match.groups.offset, 16)
      output.push(line)
      continue
    }

    if (match = line.match(/^(?<prefix>(?:\/\/\s+)?)(?<address>[0-9a-fA-F]{4,10})\s(?<suffix>.+)$/)) {
      const oldAddressStr = match.groups.address
      const oldAddress = parseInt(oldAddressStr, 16)
      const prefix = match.groups.prefix
      const suffix = match.groups.suffix
      let results = []
      let resultA = portAddress(fileOld, fileNew, oldAddress + offset, null, searchModesDefault)
      if (resultA) results.push(resultA)

      let resultB = portAddress(fileOld, fileNew, oldAddress + offset, searchModesGlobal, searchModesFast)
      if (resultB) results.push(resultB)

      results = results.sort((a, b) => b.confidence - a.confidence)

      if (results.length > 1 && results[1].new == results[0].new) {
        results.splice(1, 1)
      }

      if (results.length <= 0) {
        console.error(`Failed to find new address for ${oldAddressStr}`)
        output.push(`${line} // [x] 0x${oldAddressStr} -> Failed`)
        continue
      }

      function generateComment(result) {
        let newAddress = result.new - offset
        const newAddressStr = dec2hex(newAddress, oldAddressStr.length)
        return `0x${oldAddressStr} -> 0x${newAddressStr} (${result.delta > 0 ? '+' : ''}${result.delta} C=${result.confidence})`
      }

      let newAddress = results[0].new - offset
      const newAddressStr = dec2hex(newAddress, oldAddressStr.length)
      console.log(`Address updated: ${results.map(r => generateComment(r)).join(' | ')}`)
      if (options.addComment || results[0].confidence < 1 || results.length > 1) {
        output.push(`${prefix}${newAddressStr} ${suffix} // [P] ${results.map(r => generateComment(r)).join(' | ')}`)
      } else {
        output.push(`${prefix}${newAddressStr} ${suffix}`)
      }
      continue
    }

    output.push(line)
  }

  return output.join('\n')
}
