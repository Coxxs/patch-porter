# patch-porter

A simple `.pchtxt` porting tool.

## Usage

1. Install [Node.js](https://nodejs.org), then install `patch-porter` using npm:

    ```shell
    npm install -g patch-porter
    ```

2. Port your pchtxt:

    ```shell
    patch-porter --from=mainA --to=mainB --input=A.pchtxt --output=B.pchtxt
    ```
    - `--comment`: Add ported address as comment to the output file
    - `--arch=arm64`: Set the processor architecture for the NSO file (arm/arm64/none), default: arm64

3. Done!

## Tips
- Please keep `@flag offset_shift ...` in your pchtxt to help `patch-porter` finding the correct address
- If your pchtxt doesn't have `@flag offset_shift 0x100`, it means that the addresses in your pchtxt are not based on the NSO header offset.\
  In this case, you need to decompress your NSO file using [hactool](https://github.com/SciresM/hactool), and disable NSO mode in `patch-porter` (`--no-nso`).

    ```shell
    hactool -t nso --uncompressed mainA.raw mainA
    hactool -t nso --uncompressed mainB.raw mainB
    patch-porter --from=mainA.raw --to=mainB.raw --input=A.pchtxt --output=B.pchtxt --no-nso
    ```
- After porting, search for `[x]` in new pchtxt to find errors
- `patch-porter` does not currently update the assembly code, so some patch may still need to be updated manually

## Use in Node.js

```javascript
import { promises as fs } from 'fs'
import { portPchtxt } from 'patch-porter'

let fileA = await fs.readFile('mainA')
let fileB = await fs.readFile('mainB')
let pchtxtA = await fs.readFile('A.pchtxt', 'utf8')

let pchtxtB = await portPchtxt(fileA, fileB, pchtxtA)

await fs.writeFile('B.pchtxt', pchtxtB)
```

## Credits

- [disasm-web](https://github.com/CzBiX/disasm-web)
- [capstone](https://github.com/capstone-engine/capstone)
- [IPSwitch](https://github.com/3096/ipswitch)
