import * as lz4 from 'lz4-wasm-nodejs'

const caches = new WeakMap()

/**
 * @param {Uint8Array} buffer NSO file
 */
export function isCompressedNso(buffer) {
  const view = new DataView(buffer.buffer)
  const magic = view.getUint32(0x0)
  const flags = view.getInt32(0xC, true)

  if (magic === 0x4E534F30 && (flags & 0x7)) { // NSO0
    return true
  }
  return false
}

/**
 * @param {Uint8Array} buffer NSO file
 */
export function getNsoSegments(buffer) {
  let cache = caches.get(buffer)
  if (!cache) {
    cache = getNsoSegmentsDetail(buffer)
    caches.set(buffer, cache)
  }
  return cache
}

/**
 * @param {Uint8Array} buffer NSO file
 */
function getNsoSegmentsDetail(buffer) {
  const view = new DataView(buffer.buffer)
  const flags = view.getInt32(0xC, true)
  const metadatas = {
    text: {
      compressed: Boolean(flags & 0x1),
      fileOffset: view.getInt32(0x10, true),
      memoryOffset: view.getInt32(0x14, true),
      size: view.getInt32(0x18, true),
      compressedSize: view.getInt32(0x60, true),
    },
    rodata: {
      compressed: Boolean(flags & 0x2),
      fileOffset: view.getInt32(0x20, true),
      memoryOffset: view.getInt32(0x24, true),
      size: view.getInt32(0x28, true),
      compressedSize: view.getInt32(0x64, true),
    },
    data: {
      compressed: Boolean(flags & 0x4),
      fileOffset: view.getInt32(0x30, true),
      memoryOffset: view.getInt32(0x34, true),
      size: view.getInt32(0x38, true),
      compressedSize: view.getInt32(0x68, true),
    }
  }

  // decompress use lz4
  /**
   * @param {Uint8Array} buffer 
   * @param {object} metadata 
   */
  function getRawSegment(buffer, metadata) {
    const compressedBuffer = buffer.subarray(metadata.fileOffset, metadata.fileOffset + metadata.compressedSize)
    let decompressedBuffer
    if (metadata.compressed) {
      try {
        const tempBuffer = new Uint8Array(compressedBuffer.length + 4)
        const tempDataView = new DataView(tempBuffer.buffer)
        tempDataView.setInt32(0, metadata.size, true)
        tempBuffer.set(compressedBuffer, 4)
        decompressedBuffer = lz4.decompress(tempBuffer)
      } catch (err) {
        console.log(err)
        throw new Error('Decompression failed')
      }
    } else {
      decompressedBuffer = compressedBuffer
    }
    if (decompressedBuffer.length !== metadata.size) {
      throw new Error(`Segment size mismatch, ${decompressedBuffer.length} != ${metadata.size}`)
    }
    return {
      buffer: decompressedBuffer,
      start: metadata.memoryOffset,
      end: metadata.memoryOffset + metadata.size,
    }
  }

  const segments = {
    text: getRawSegment(buffer, metadatas.text),
    rodata: getRawSegment(buffer, metadatas.rodata),
    data: getRawSegment(buffer, metadatas.data),
  }
  return segments
}