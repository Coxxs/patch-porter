let lz4

if (typeof process !== 'undefined' && process.release && process.release.name === 'node') {
  lz4 = await import('lz4-wasm-nodejs')
} else {
  try {
    lz4 = await import('lz4-wasm/lz4_wasm_bg.js')
  } catch (err) {
    console.warn('Failed to load lz4-wasm, decompression will fail if needed.', err)
    lz4 = {
      decompress: () => { throw new Error('lz4-wasm not loaded') },
      compress: () => { throw new Error('lz4-wasm not loaded') }
    }
  }
}

export const compress = lz4.compress
export const decompress = lz4.decompress
