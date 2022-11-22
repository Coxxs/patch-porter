#! /usr/bin/env node
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
  .help()
  .alias('help', 'h').argv;

(async () => {
  const { portPchtxt } = await import('../port.mjs')

  let fileOld = await fs.readFile(argv.from)
  let fileNew = await fs.readFile(argv.to)

  let pchtxtOld = await fs.readFile(argv.input, 'utf8')
  let pchtxtNew = portPchtxt(fileOld, fileNew, pchtxtOld)

  await fs.writeFile(argv.output, pchtxtNew)
})()