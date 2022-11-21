import { promises as fs } from 'fs'
import { updatePchtxt } from "./port.mjs"

// 1. Install [Node.js](https://nodejs.org/)
// 2. Decompress NSO using hactool: hactool -t nso main --uncompressed main.decompressed
let fileOld = await fs.readFile('1.2.0.decompressed')
let fileNew = await fs.readFile('1.2.1.decompressed')

let oldPchtxt = await fs.readFile('patch_1.2.0.pchtxt', 'utf8')
let newPchtxt = updatePchtxt(fileOld, fileNew, oldPchtxt)

fs.writeFile('patch_1.2.1.pchtxt', newPchtxt)

// 3. Use Node.js to run this script: node example.mjs
// 4. Search for "[!]" in new pchtxt to find errors
// 5. Update nsobid in new pchtxt manually