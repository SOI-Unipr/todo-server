'use strict';

import program from 'commander';
import dotenv from 'dotenv';
import lodash from "lodash";
import {readFileSync} from 'fs';

const {merge} = lodash;

function assertPort(port, program, excode) {
    if (port <= 1024 || port > 65535) {
        console.error(`Invalid port (must be between 1025 and 65535): ${port}`);
        program.outputHelp();
        process.exit(excode);
    }
}

/**
 * Prepares the configuration from environment variables.
 * @return {{config: {iface: string, port: number, oidc: {redirect: string, clientId: string, secret: string}}}} Configuration
 */
function configFromEnv() {
    dotenv.config();
    const cfg = {};
    if (process.env.IFACE) cfg.iface = process.env.IFACE;
    if (process.env.PORT) cfg.port = process.env.PORT;
    if (process.env.OIDC_CLIENT_ID) (cfg.oidc = cfg.oidc || {}).clientId = process.env.OIDC_CLIENT_ID;
    if (process.env.OIDC_SECRET) (cfg.oidc = cfg.oidc || {}).secret = process.env.OIDC_SECRET;
    if (process.env.OIDC_REDIRECT) (cfg.oidc = cfg.oidc || {}).redirect = process.env.OIDC_REDIRECT;
    return cfg;
}

/**
 * Reads the command line and returns the parsed configuration.
 * @return {{config: {iface: string, port: number, oidc: {redirect: string, clientId: string, secret: string}}}} Configuration
 */
export function parse() {
    const {version} = JSON.parse(readFileSync('./package.json'));

    // generic properties
    program
        .version(version)
        .option('-i, --iface <interface>', 'The interface the service will listen to for requests', '0.0.0.0')
        .option('-E, --no-env', 'Ignores the .env file')
        .option('-p, --port <port>', 'The port number the service will listen to for requests', p => parseInt(p, 10), 8000)
        .option('-c, --oidc-client-id <id>', 'OpenID Connect client ID')
        .option('-s, --oidc-secret <secret>', 'OpenID Connect client secret code')
        .option('-r, --oidc-redirect <uri>', 'OpenID Connect redirect URI')
    ;

    // parses command line
    program.parse(process.argv);
    assertPort(program.port, program, 2);

    const env = program.noEnv ? {} : configFromEnv();

    const config = merge(env, {
        iface: program.iface,
        port: program.port,
        oidc: {
            clientId: program.oidcClientId,
            secret: program.oidcSecret,
            redirect: program.oidcRedirect
        },
    });

    return {config};
}

export default parse;
