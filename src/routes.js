'use strict';

function sequencer() {
    let i = 1;
    return function () {
        const n = i;
        i++;
        return n;
    }
}

class Task {
    constructor(id, description) {
        this._id = id;
        this._description = description;
        this._timestamp = new Date();
    }

    //@formatter:off
    get id() { return this._id; }
    get description() { return this._description; }
    set description(description) { this._description = description; }
    get timestamp() { return this._timestamp; }
    //@formatter:on
}

const seq = sequencer();
const tasks = [];

for (let i = 0; i < 5; i++) {
    const id = seq();
    tasks.push(new Task(id, `Spend more time hacking #${id}`));
}

function toDTO(task) {
    return {
        id: task.id,
        description: task.description,
        timestamp: task.timestamp // should be converted according to ISO8601
    };
}

function routes(app) {

    app.get('/tasks', (req, resp) => {
        console.debug('Received call to /tasks', {query: req.query});

        const objects = tasks.map(toDTO);
        resp.json({
            total: objects.length,
            results: objects
        });
    });

    app.post('/task', (req, resp) => {
        // TODO this API saves a new task
        resp.status(418);
        resp.json("I'm a teapot");
    });

    app.put('/task/:id', (req, resp) => {
        // TODO this API updates an existing task
        resp.status(418);
        resp.json("I'm a teapot");
    });

    app.delete('/task/:id', (req, resp) => {
        // TODO this API deletes an existing task
        resp.status(418);
        resp.json("I'm a teapot");
    });
}

module.exports = {routes};
