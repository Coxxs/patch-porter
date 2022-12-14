# patch-porter

A simple `.pchtxt` porting tool.

## Usage

1. Install [Node.js](https://nodejs.org), then install `patch-porter` using npm:
    - `npm install -g patch-porter`
2. Decompress NSO using [hactool](https://github.com/SciresM/hactool):
    - `hactool -t nso main --uncompressed main.raw`
3. Port your pchtxt:
    - `patch-porter --from=mainA.raw --to=mainB.raw --input=A.pchtxt --output=B.pchtxt`
4. Done!

## Tips
- Please keep `@flag offset_shift ...` in your pchtxt to help `patch-porter` finding the correct address
- After porting, search for `[x]` in new pchtxt to find errors
- `patch-porter` does not currently update the assembly code, so some patch may still need to be updated manually

## Use in Node.js

```javascript
import { promises as fs } from 'fs'
import { portPchtxt } from 'patch-porter'

let fileA = await fs.readFile('mainA.raw')
let fileB = await fs.readFile('mainB.raw')
let pchtxtA = await fs.readFile('A.pchtxt', 'utf8')

let pchtxtB = await portPchtxt(fileA, fileB, pchtxtA)

await fs.writeFile('B.pchtxt', pchtxtB)
```
