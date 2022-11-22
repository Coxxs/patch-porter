#! /usr/bin/env node
const { existsSync } = require('fs');
const yargs = require('yargs')
const fs = require('fs').promises

const argv = yargs
  .option('from', {
    description: 'The decompressed NSO file to port from',
    type: 'string',
    demandOption: true,
  })
  .option('to', {
    description: 'The decompressed NSO file to port to',
    type: 'string',
    demandOption: true,
  })
  .option('input', {
    description: 'The input pchtxt file',
    alias: 'i',
    type: 'string',
    demandOption: true,

  })
  .option('output', {
    description: 'Output path for the new pchtxt file',
    alias: 'o',
    type: 'string',
    demandOption: true,
  })
  .option('overwrite', {
    description: 'Overwrite the output file',
    alias: 'w',
    type: 'boolean',
    default: false,
  })
  .help()
  .alias('help', 'h').argv;

(async () => {
  const { portPchtxt } = await import('../port.mjs')

  let fileOld = await fs.readFile(argv.from)
  let fileNew = await fs.readFile(argv.to)

  if (argv.from == argv.to) {
    console.error('Error: From and to paths are the same')
    return
  }

  if (argv.input == argv.output) {
    console.error('Error: Input and output paths are the same')
    return
  }

  if (existsSync(argv.output) && !argv.overwrite) {
    console.error('Error: Output pchtxt already exists, use -w to overwrite')
    return
  }

  let pchtxtOld = await fs.readFile(argv.input, 'utf8')
  let pchtxtNew = portPchtxt(fileOld, fileNew, pchtxtOld)

  await fs.writeFile(argv.output, pchtxtNew)
  console.log(`Output pchtxt saved to: ${argv.output}`)
})()