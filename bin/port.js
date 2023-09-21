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
  .option('comment', {
    description: 'Add ported address as comment to the output file',
    type: 'boolean',
    default: false,
  })
  .option('arch', {
    description: 'Set the processor architecture for the NSO file (arm/arm64/none)',
    type: 'string',
    default: 'arm64',
  })
  .help()
  .alias('help', 'h').argv;

(async () => {
  const { portPchtxt } = await import('../port.mjs')

  if (argv.from == argv.to) {
    console.error('Error: From and to paths are the same')
    return
  }

  if (existsSync(argv.output) && !argv.overwrite) {
    console.error('Error: Output pchtxt already exists, use -w to overwrite')
    return
  }

  let options = {}

  if (argv.comment) {
    options.addComment = true
  }
  if (argv.arch) {
    options.arch = argv.arch
  }

  let fileOld = await fs.readFile(argv.from)
  let fileNew = await fs.readFile(argv.to)

  const inputs = Array.isArray(argv.input) ? argv.input : [argv.input]
  const outputs = Array.isArray(argv.output) ? argv.output : [argv.output]

  if (inputs.length !== outputs.length) {
    console.error('Error: The number of inputs does not match the number of outputs')
  }

  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i]
    const output = outputs[i]
    if (input == output) {
      console.error('Error: Input and output paths are the same')
      return
    }

    let pchtxtOld = await fs.readFile(input, 'utf8')
    let pchtxtNew = await portPchtxt(fileOld, fileNew, pchtxtOld, options)

    await fs.writeFile(output, pchtxtNew)
    console.log(`Output pchtxt saved to: ${output}`)
  }
})()