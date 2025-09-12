import { indexOfAll } from "./lib/fast-index-of-all.mjs"
import { getNsoSegments, isCompressedNso, getNsobid } from './lib/nso.mjs'
import { Const, Capstone, loadCapstone } from 'capstone-wasm'
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
 * @param {Uint8Array} fileOld
 * @param {Uint8Array} fileNew
 * @param {number} address
 * @param {number} offset
 * @param {object} searchMode
 * @returns {Array<object>} results
 */
function portAddressSearchMode(fileOld, fileNew, address, offset = 0, searchMode = searchModesDefault[0]) {
  if (!Number.isInteger(address)) {
    throw new Error('address must be an integer')
  }
  let { start, end, length, step, range } = searchMode
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
 * @param {Capstone | null} capstone
 * @param {Uint8Array} fileOld
 * @param {Uint8Array} fileNew
 * @param {number} address
 * @param {object} searchMode
 * @returns {Promise<number | false>} offset
 */
async function getEstimatedOffset(capstone, fileOld, fileNew, address, searchMode = searchModesGlobal[0]) {
  const results = portAddressSearchMode(fileOld, fileNew, address, 0, searchMode)
  // console.log(`Estimating offset with search mode ${JSON.stringify(searchMode)}, results ${JSON.stringify(results)}`)
  if (results.length == 0) return false

  const deltas = results.map(result => result.delta)
  deltas.sort((a, b) => a - b)
  const median = deltas[Math.floor(deltas.length / 2)]

  if (deltas.filter(delta => delta > median - 0x20 && delta < median + 0x20).length >= 3) {
    return median
  }
  if (capstone) {
    let confidence = await getPortConfidenceByInstructions(capstone, fileOld, fileNew, address, address + median)
    if (confidence > 0.7) {
      return median
    }  
  }
  return false
}

/**
 * @param {Capstone} capstone 
 * @param {Uint8Array} fileOld 
 * @param {Uint8Array} fileNew 
 * @param {number} addressOld 
 * @param {number} addressNew 
 * @param {number} start 
 * @param {number} end 
 * @returns {Promise<number>} confidence
 */
async function getPortConfidenceByInstructions(capstone, fileOld, fileNew, addressOld, addressNew, start = -16, end = 16) {
  if (!capstone) {
    throw new Error('capstone is required')
  }
  if (start % 4 !== 0 || end % 4 !== 0) {
    throw new Error('offset not aligned with instructions')
  }

  let confidences = []

  for (let i = start; i < end; i += 4) {
    const dataOld = fileOld.subarray(addressOld + i, addressOld + i + 4)
    const dataNew = fileNew.subarray(addressNew + i, addressNew + i + 4)
    let insnsOld
    let insnsNew

    try {
      insnsOld = capstone.disasm(dataOld, { address: 0xcafe880000000 })
    } catch (err) {
      insnsOld = err
    }
    try {
      insnsNew = capstone.disasm(dataNew, { address: 0xcafe880000000 })
    } catch (err) {
      insnsNew = err
    }

    let confidence = 0
    if (insnsOld instanceof Error || insnsNew instanceof Error) {
      if (Buffer.compare(dataOld, dataNew) === 0) {
        confidence = 1
      } else if (insnsOld instanceof Error && insnsNew instanceof Error) {
        confidence = 0.1
      } else {
        confidence = 0
      }
      // console.log('has error, confidence = ' + confidence, insnsOld instanceof Error, insnsNew instanceof Error)
    } else if (insnsOld.length === 1 && insnsNew.length === 1) {
      // console.log(insnsOld[0].mnemonic, insnsOld[0].opStr, '->', insnsNew[0].mnemonic, insnsNew[0].opStr)
      if (insnsOld[0].mnemonic === insnsNew[0].mnemonic) {
        confidence += 0.2
        if (insnsOld[0].opStr === insnsNew[0].opStr) {
          confidence += 0.8
        } else {
          const regex = /#0xcafe8[0-9a-f]+/g
          const noAddrOpStrOld = insnsOld[0].opStr.replace(regex, '#0xDUMMY')
          const noAddrOpStrNew = insnsNew[0].opStr.replace(regex, '#0xDUMMY')
          if (noAddrOpStrOld === noAddrOpStrNew) {
            confidence += 0.75
          }
        }
      }
    }
    confidences.push(confidence)
  }

  const average = arr => arr.reduce( ( p, c ) => p + c, 0 ) / arr.length;
  return average(confidences)
}

/**
 * @param {Capstone} capstone 
 * @param {Uint8Array} file 
 * @param {number} fileAddress 
 * @param {number} capstoneAddress 
 * @returns {Promise<string>} assembly instruction
 */
async function getInstruction(capstone, file, fileAddress, capstoneAddress) {
  if (!capstone) {
    throw new Error('capstone is required')
  }
  const data = file.subarray(fileAddress, fileAddress + 4)
  let insns
  try {
    insns = capstone.disasm(data, { address: capstoneAddress })
  } catch (err) {
    insns = []
  }

  if (insns.length !== 1) {
    return null
  } else {
    return insns[0].mnemonic + ' ' + insns[0].opStr
  }
}

/**
 * @param {Uint8Array} fileOld
 * @param {Uint8Array} fileNew
 * @param {number} address 
 * @param {Array<object>} searchModesOffset
 * @param {Array<object>} searchModes
 * @param {Capstone | null} capstone
 * @returns {Promise<object | false>} address
 */
export async function portAddress(fileOld, fileNew, address, searchModesOffset = searchModesGlobal, searchModes = searchModesFast, capstone = null) {
  if (!Number.isInteger(address)) {
    throw new Error('address must be an integer')
  }
  let estimatedOffset
  if (searchModesOffset) {
    for (const searchMode of searchModesOffset) {
      estimatedOffset = await getEstimatedOffset(capstone, fileOld, fileNew, address, searchMode)
      // console.log(`Unable to find estimated offset!`)
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
    const instructionsConfidence = capstone ? Math.min(
      await getPortConfidenceByInstructions(capstone, fileOld, fileNew, address, address + median),
      await getPortConfidenceByInstructions(capstone, fileOld, fileNew, address, address + median, 0, 4)
    ) : null
    if (count >= 2 && count > deltas.length * 0.3) {
      const confidence = instructionsConfidence !== null ? Math.min(1, instructionsConfidence) : 1
      results.push({ old: address, new: address + median, delta: median, confidence: confidence })
      break
    } else if (deltas.length == 1) {
      const confidence = instructionsConfidence !== null ? Math.min(0.6, instructionsConfidence) : 0.6
      results.push({ old: address, new: address + median, delta: median, confidence: Math.min(0.6, confidence) })
    }
  }
  if (searchModesOffset) {
    const instructionsConfidence = capstone ? Math.min(
      await getPortConfidenceByInstructions(capstone, fileOld, fileNew, address, address + estimatedOffset),
      await getPortConfidenceByInstructions(capstone, fileOld, fileNew, address, address + estimatedOffset, 0, 4)
    ) : null
    const confidence = instructionsConfidence !== null ? Math.min(0.3, instructionsConfidence) : 0.3
    results.push({ old: address, new: address + estimatedOffset, delta: estimatedOffset, confidence: confidence })
  }
  results = results.sort((a, b) => b.confidence - a.confidence)
  return results.length > 0 ? results[0] : false
}

async function portNsoAddressAndCheck(capstone, fileOld, fileNew, oldAddress, offset) {
  if (offset != 0x100) {
    console.error('Your pchtxt did not set the correct NSO offset (@flag offset_shift 0x100), please disable NSO mode (--no-nso) or fix the pchtxt.')
    return []
  }
  let segmentsNew = getNsoSegments(fileNew)
  let segmentsOld = getNsoSegments(fileOld)

  let segmentOld
  let segmentNew
  let segmentName
  for (let [_segmentName, _segmentOld] of Object.entries(segmentsOld)) {
    if (oldAddress >= _segmentOld.start && oldAddress < _segmentOld.end) {
      segmentOld = _segmentOld
      segmentNew = segmentsNew[_segmentName]
      segmentName = _segmentName
      break
    }
  }

  if (!segmentOld || !segmentNew || !segmentName) {
    console.error(`${oldAddress.toString(16)} is not in a supported segment`)
    return []
  }

  let results = []

  let resultA = await portAddress(segmentOld.buffer, segmentNew.buffer, oldAddress - segmentOld.start, null, searchModesDefault, capstone)
  if (resultA) results.push(resultA)

  let resultB = await portAddress(segmentOld.buffer, segmentNew.buffer, oldAddress - segmentOld.start, searchModesGlobal, searchModesFast, capstone)
  if (resultB) results.push(resultB)

  results = results.sort((a, b) => b.confidence - a.confidence)
  
  if (capstone) {
    const oldInstructionStr = await getInstruction(capstone, segmentOld.buffer, oldAddress - segmentOld.start, oldAddress)
    for (let result of results) {
      result.oldInst = oldInstructionStr
      result.newInst = await getInstruction(capstone, segmentNew.buffer, result.new, result.new + segmentNew.start)
    }  
  }

  if (results.length > 1 && results[1].new == results[0].new) {
    results.splice(1, 1)
  }

  // convert addresses back to file address
  for (let result of results) {
    result.segmentName = segmentName
    result.relativeOld = result.old
    result.relativeNew = result.new
    result.old += segmentOld.start + offset
    result.new += segmentNew.start + offset
  }
  
  return results
}

async function portAddressAndCheck(capstone, fileOld, fileNew, oldAddress, offset) {
  let results = []

  let resultA = await portAddress(fileOld, fileNew, oldAddress + offset, null, searchModesDefault, capstone)
  if (resultA) results.push(resultA)

  let resultB = await portAddress(fileOld, fileNew, oldAddress + offset, searchModesGlobal, searchModesFast, capstone)
  if (resultB) results.push(resultB)

  results = results.sort((a, b) => b.confidence - a.confidence)
  
  if (capstone) {
    const oldInstructionStr = await getInstruction(capstone, fileOld, oldAddress + offset, oldAddress)
    for (let result of results) {
      result.oldInst = oldInstructionStr
      result.newInst = await getInstruction(capstone, fileNew, result.new, result.new - offset)
    }  
  }

  if (results.length > 1 && results[1].new == results[0].new) {
    results.splice(1, 1)
  }

  return results
}

/**
 * @param {Buffer | Uint8Array} fileOld 
 * @param {Buffer | Uint8Array} fileNew 
 * @param {string} pchtxt 
 * @param {object} options 
 * @returns {Promise<string>} pchtxt
 */
export async function portPchtxt(fileOld, fileNew, pchtxt, options) {
  options = {
    addComment: false,
    arch: 'arm64',
    nso: true,
    ...options,
  }
  const startTime = Date.now()

  let capstone
  if (options.arch === 'arm') {
    await loadCapstone()
    capstone = new Capstone(Const.CS_ARCH_ARM, Const.CS_MODE_ARM)
  } else if (options.arch === 'arm64') {
    await loadCapstone()
    capstone = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM)
  } else if (options.arch === 'none') {
    capstone = null
  } else {
    throw new Error(`invalid arch: ${options.arch}`)
  }

  if (fileOld instanceof Buffer) {
    fileOld = new Uint8Array(fileOld)
  }
  if (fileNew instanceof Buffer) {
    fileNew = new Uint8Array(fileNew)
  }

  if (!options.nso && (isCompressedNso(fileOld) || isCompressedNso(fileNew))) {
    throw new Error('Your NSO file is compressed, please enable NSO mode (--nso) or decompress the NSO manually.')
  }

  try {
    const lines = pchtxt.replaceAll('\r\n', '\n').split('\n')
    const output = []
    const portCache = new Map()
  
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

        let results = portCache.get(oldAddress + offset) // may need structuredClone in the future
        if (!results) {
          if (options.nso) {
            results = await portNsoAddressAndCheck(capstone, fileOld, fileNew, oldAddress, offset)
          } else {
            results = await portAddressAndCheck(capstone, fileOld, fileNew, oldAddress, offset)
          }
          portCache.set(oldAddress + offset, results) // may need structuredClone in the future
        }
  
        if (results.length <= 0) {
          console.error(`Failed to find new address for ${oldAddressStr}`)
          output.push(`${line} // [x] 0x${oldAddressStr} -> Failed`)
          continue
        }
  
        function generateComment(result) {
          function formatConfidence(c) {
            if (Math.abs(c % 1) < 0.0000001) {
              return Math.round(c)
            }
            return c.toFixed(2)
          }

          if (result.segmentName) {
            const oldRelativeAddressStr = dec2hex(result.relativeOld, 0)
            const newRelativeAddressStr = dec2hex(result.relativeNew, 0)
            const oldInstStr = result.oldInst ? ` (${result.oldInst})` : ''
            const newInstStr = result.newInst ? ` (${result.newInst})` : ''
    
            return `${result.delta > 0 ? '+' : ''}${result.delta} C=${formatConfidence(result.confidence)} .${result.segmentName}+0x${oldRelativeAddressStr}${oldInstStr} -> .${result.segmentName}+0x${newRelativeAddressStr}${newInstStr}`  
          } else {
            let newAddress = result.new - offset
            const newAddressStr = dec2hex(newAddress, oldAddressStr.length)
            const oldInstStr = result.oldInst ? ` (${result.oldInst})` : ''
            const newInstStr = result.newInst ? ` (${result.newInst})` : ''
    
            return `${result.delta > 0 ? '+' : ''}${result.delta} C=${formatConfidence(result.confidence)} 0x${oldAddressStr}${oldInstStr} -> 0x${newAddressStr}${newInstStr}`  
          }
        }
  
        let newAddress = results[0].new - offset
        const newAddressStr = dec2hex(newAddress, oldAddressStr.length)
        console.log(`Address updated: ${results.map(r => generateComment(r)).join(' | ')}`)
        if (options.addComment || results[0].confidence < 0.8 || results.length > 1) {
          output.push(`${prefix}${newAddressStr} ${suffix} // ${results[0].confidence >= 0.3 ? '[P]' : '[x]'} ${results.map(r => generateComment(r)).join(' | ')}`)
        } else {
          output.push(`${prefix}${newAddressStr} ${suffix}`)
        }
        continue
      }
  
      output.push(line)
    }
  
  
    console.log(`Finished in ${(Date.now() - startTime) / 1000}s.`)
    return output.join('\n')  
  } finally {
    if (capstone) capstone.close()
  }
}
