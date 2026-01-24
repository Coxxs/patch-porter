/**
 * @param {Uint8Array} uint8Array
 * @returns {string} hex string
 */
export function toHex(uint8Array) {
  return Array.from(uint8Array)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase()
}

/**
 * @param {string} hexString
 * @returns {Uint8Array}
 */
export function fromHex(hexString) {
  if (hexString.length % 2 !== 0) {
    throw new Error('Invalid hex string')
  }
  const bytes = new Uint8Array(hexString.length / 2)
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16)
  }
  return bytes
}

/**
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {number} 0 if equal, nonzero otherwise
 */
export function compare(a, b) {
  if (a.length !== b.length) return a.length - b.length
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i]
  }
  return 0
}
