function dec2hex(number, length) {
  return number.toString(16).padStart(length, '0').toUpperCase()
}

const searchModesDefault = [
  { start: 16, end: -16, length: 8, step: -4, range: 0x1000 },
  { start: 16, end: -16, length: 12, step: -4, range: 0x1000 },
  { start: 16, end: -16, length: 16, step: -4, range: 0x1000 },

  { start: 16, end: -16, length: 8, step: -4, range: 0x80000 },
  { start: 16, end: -16, length: 12, step: -4, range: 0x80000 },
  { start: 16, end: -16, length: 16, step: -4, range: 0x80000 },

  { start: 32, end: -32, length: 8, step: -4, range: 0x80000 },
  { start: 32, end: -32, length: 12, step: -4, range: 0x80000 },
  { start: 32, end: -32, length: 16, step: -4, range: 0x80000 },
]

/**
 * @param {Buffer} buffer Buffer to search
 * @param {Buffer} search Buffer to search for
 * @returns {Array<number>} Array of indexes
 */
function indexOfAll(buffer, search) {
  const result = []
  let offset = 0
  while (true) {
    const index = buffer.indexOf(search, offset)
    if (index === -1) break
    result.push(index)
    offset = index + 1
  }
  return result
}

/**
 * 
 * @param {Buffer} fileOld
 * @param {Buffer} fileNew
 * @param {number} address 
 * @param {Array<object>} searchModes
 * @returns {number | false} delta
 */
export function findNewOffset(fileOld, fileNew, address, searchModes = searchModesDefault) {
  for (const searchMode of searchModes) {
    const { start, end, length, step, range } = searchMode
    if (start == end && step == 0) {
      step = 1 // prevent infinite loop
    }
    if (start > end && step > 0 || start < end && step < 0) {
      throw new Error(`Search mode ${JSON.stringify(searchMode)} will cause an infinite loop`)
    }
    // limit search range
    let startOffset
    let searchOld
    let searchNew
    if (Number.isInteger(range)) {
      startOffset = Math.max(0, address - range)
      searchOld = fileOld.subarray(startOffset, address + range)
      searchNew = fileNew.subarray(startOffset, address + range)
    } else {
      startOffset = 0
      searchOld = fileOld
      searchNew = fileNew
    }
    for (let i = start; start > end ? i >= end : i <= end ; i += step) {
      const ptr = address + i
      const data = fileOld.subarray(ptr, ptr + length)
      const indexs = indexOfAll(searchNew, data)
      if (indexs.length == 0) continue
      if (indexs.length > 1) continue
      let delta = indexs[0] + startOffset - ptr
      // console.log(`Found with mode ${JSON.stringify(searchMode)}, delta ${delta}`)
      return delta
    }
  }
  return false
}

/**
 * 
 * @param {Buffer} fileOld 
 * @param {Buffer} fileNew 
 * @param {string} pchtxt 
 * @param {Array<object>} searchModes 
 * @returns {string} new pchtxt
 */
export function updatePchtxt(fileOld, fileNew, pchtxt, searchModes = searchModesDefault) {
  const lines = pchtxt.replaceAll('\r\n', '\n').split('\n')
  const output = []

  let offset = 0
  for (const line of lines) {
    let match
    if (match = line.match(/^@flag\s+offset_shift\s+0x(?<offset>[0-9a-fA-F]+)$/)) {
      offset = parseInt(match.groups.offset, 16)
      output.push(line)
      continue
    }

    if (match = line.match(/^(?<prefix>(?:\\\s+)?)(?<address>[0-9a-fA-F]{2,10})\s(?<suffix>.+)$/)) {
      const oldAddressStr = match.groups.address
      const oldAddress = parseInt(oldAddressStr, 16)
      const prefix = match.groups.prefix
      const suffix = match.groups.suffix
      const delta = findNewOffset(fileOld, fileNew, oldAddress + offset, searchModes)
      if (delta === false) {
        console.error(`Failed to find new address for ${oldAddressStr}`)
        output.push(`${line} // [!] Failed to find new address in new file`)
        continue
      }
      const newAddress = oldAddress + delta
      const newAddressStr = dec2hex(newAddress, oldAddressStr.length)
      console.log(`Address updated: 0x${oldAddressStr} -> 0x${newAddressStr} (${delta})`)
      output.push(`${prefix}${newAddressStr} ${suffix}`)
      continue
    }

    output.push(line)
  }

  return output.join('\n')
}

