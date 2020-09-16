'use strict';

const util = require('util');

// utilities
const uuid = require('uuid').v4;

// express
const express = require('express');
const methodOverride = require('method-override');
const bodyParser = require('body-parser');
const compression = require('compression');

// own modules
const opts = require('./options');
const {routes} = require('./routes');

// creates the configuration options and the logger
const options = opts();

/**
 * Initializes the application middlewares.
 *
 * @param {Object} app Express application
 * @returns {void}
 */
function init(app) {
    app.use(compression());
    app.use(methodOverride());
    app.use(bodyParser.json());
    app.use(bodyParser.urlencoded({extended: true}));

    // sets the correlation id of any incoming requests
    app.use((req, res, next) => {
        req.correlationId = req.get('X-Request-ID') || uuid();
        res.set('X-Request-ID', req.id);
        next();
    });
}

/**
 * Installs fallback error handlers.
 *
 * @param app Express application
 * @returns {void}
 */
function fallbacks(app) {
    // generic error handler => err.status || 500 + json
    // NOTE keep the `next` parameter even if unused, this is mandatory for Express 4
    /* eslint-disable-next-line no-unused-vars */
    // noinspection JSUnusedLocalSymbols
    app.use((err, req, res, next) => {
        const errmsg = err.message || util.inspect(err);
        console.error(`Unexpected error occurred while calling ${req.path}: ${errmsg}`);
        res.status(err.status || 500);
        res.json({error: err.message || 'Internal server error'});
    });

    // if we are here, then there's no valid route => 400 + json
    // NOTE keep the `next` parameter even if unused, this is mandatory for Express 4
    /* eslint-disable no-unused-vars */
    // noinspection JSUnusedLocalSymbols
    app.use((req, res, next) => {
        console.error(`Route not found to ${req.path}`);
        res.status(404);
        res.json({error: 'Not found'});
    });
}

const app = express();
init(app);
routes(app);
fallbacks(app);

const {iface, port} = options.config;
app.listen(port, iface, () => {
    console.info(`Server listening: http://${iface}:${port}`);
});
