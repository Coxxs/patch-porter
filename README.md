# patch-porter

A simple `.pchtxt` porting tool.

## Usage

1. Install [Node.js](https://nodejs.org), then install `patch-porter` using npm:

    ```shell
    npm install -g patch-porter
    ```

2. Decompress NSO using [hactool](https://github.com/SciresM/hactool):

    ```shell
    hactool -t nso --uncompressed main.raw main
    ```

3. Port your pchtxt:

    ```shell
    patch-porter --from=mainA.raw --to=mainB.raw --input=A.pchtxt --output=B.pchtxt
    ```
    - `--comment`: Add ported address as comment to the output file
    - `--arch=arm64`: Set the processor architecture for the NSO file (arm/arm64/none)

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

## Credits

- [disasm-web](https://github.com/CzBiX/disasm-web)
- [capstone](https://github.com/capstone-engine/capstone)
- [IPSwitch](https://github.com/3096/ipswitch)
