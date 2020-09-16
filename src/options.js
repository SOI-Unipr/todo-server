'use strict';

function assertPort(port, program, excode) {
    if (port <= 1024 || port > 65535) {
        console.error(`Invalid port (must be between 1025 and 65535): ${port}`);
        program.outputHelp();
        process.exit(excode);
    }
}

function parse() {
    const {version} = require('../package.json');
    const program = require('commander');

    // generic properties
    program
        .version(version)
        .option('-i, --iface <interface>', 'The interface the service will listen to for requests', '0.0.0.0')
        .option('-p, --port <port>', 'The port number the service will listen to for requests', p => parseInt(p), 8000)
    ;

    // parses command line
    program.parse(process.argv);
    assertPort(program.port, program, 2);

    const config = {
        iface: program.iface,
        port: program.port
    };

    return {config};
}

module.exports = parse;
