/*
 * Testes do f5TcpdumpWorker.js SEM F5 e sem processo real: o child_process e simulado.
 *
 *   node test/worker.test.js                       (a partir de onbox/lx)
 *
 * Para rodar dentro do Node do BIG-IP sem gravar arquivo, o fonte do worker pode vir
 * em global.__WORKER_SRC__ (ver onbox/README.md).
 */
"use strict";

var fs = require("fs");
var path = require("path");
var assert = require("assert");
var EventEmitter = require("events").EventEmitter;

var WORKER_SRC = (typeof global.__WORKER_SRC__ === "string")
    ? global.__WORKER_SRC__
    : fs.readFileSync(path.join(__dirname, "..", "nodejs", "f5TcpdumpWorker.js"), "utf8");

// ---- infraestrutura de simulacao ---------------------------------------------------

var spawnCalls = [];
var nextChildren = [];

function scriptedChild(spec) {
    var child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.stdin = new EventEmitter();
    child.signals = [];
    child.written = null;
    child.kill = function (signal) {
        child.signals.push(signal);
        setImmediate(function () { child.emit("close", null, signal); });
    };
    child.stdin.end = function (data) {
        child.written = data;
        if (spec.hang) {
            return;
        }
        setImmediate(function () {
            if (spec.error) {
                child.emit("error", spec.error);
                return;
            }
            if (spec.stdout) {
                child.stdout.emit("data", Buffer.from(spec.stdout));
            }
            if (spec.stderr) {
                child.stderr.emit("data", Buffer.from(spec.stderr));
            }
            child.emit("close", spec.code === undefined ? 0 : spec.code, null);
        });
    };
    return child;
}

function loadWorker() {
    var mod = {exports: {}};
    var fakeRequire = function (name) {
        if (name === "child_process") {
            return {
                spawn: function (cmd, args, opts) {
                    spawnCalls.push({cmd: cmd, args: args, opts: opts});
                    return nextChildren.shift();
                }
            };
        }
        return require(name);
    };
    new Function("module", "exports", "require", WORKER_SRC)(mod, mod.exports, fakeRequire);
    return mod.exports;
}

function newWorker() {
    var Worker = loadWorker();
    var worker = new Worker();
    worker.logger = {info: function () {}, error: function () {}, warning: function () {}};
    return {worker: worker, Worker: Worker};
}

function invoke(worker, method, body) {
    // completeRestOperation resolve a promessa DA OPERACAO recebida - varios pedidos
    // podem estar em andamento no mesmo worker ao mesmo tempo.
    worker.completeRestOperation = function (operation) {
        operation.resolve(operation);
    };
    return new Promise(function (resolve) {
        var op = {
            statusCode: null,
            body: undefined,
            contentType: null,
            resolve: resolve,
            getBody: function () { return body; },
            setBody: function (b) { op.body = b; },
            setStatusCode: function (s) { op.statusCode = s; },
            setContentType: function (c) { op.contentType = c; }
        };
        worker["on" + method](op);
    });
}

function reset() {
    spawnCalls.length = 0;
    nextChildren.length = 0;
}

var tests = [];
function test(name, fn) { tests.push({name: name, fn: fn}); }

// ---- casos ------------------------------------------------------------------------

test("GET descreve o endpoint e nao executa nada", function () {
    var w = newWorker().worker;
    return invoke(w, "Get").then(function (op) {
        assert.strictEqual(op.statusCode, 200);
        assert.strictEqual(op.body.name, "f5_tcpdump");
        assert.strictEqual(spawnCalls.length, 0);
    });
});

test("metadados do worker (caminho REST publico)", function () {
    var Worker = loadWorker();
    assert.strictEqual(Worker.prototype.WORKER_URI_PATH, "shared/f5_tcpdump");
    assert.strictEqual(Worker.prototype.isPublic, true);
});

test("POST valido: argv fixo, pedido por stdin e resposta repassada", function () {
    var w = newWorker().worker;
    var request = {node_port: 15000, host: "10.100.2.1", count: 20, timeout_sec: 8};
    var reply = {status: "ok", exit_status: 124, summary: {total_packets: 4}, packets: []};
    nextChildren.push(scriptedChild({stdout: JSON.stringify(reply) + "\n"}));
    return invoke(w, "Post", request).then(function (op) {
        assert.strictEqual(op.statusCode, 200);
        assert.deepStrictEqual(op.body, reply);
        assert.strictEqual(op.contentType, "application/json");
        assert.strictEqual(spawnCalls.length, 1);
        assert.strictEqual(spawnCalls[0].cmd, "/usr/bin/sudo");
        assert.deepStrictEqual(spawnCalls[0].args, ["-n", "/shared/f5_tcpdump/f5_tcpdump.py"]);
        assert.ok(!spawnCalls[0].opts.shell, "nunca usar shell");
    });
});

test("pedido chega ao script exatamente como serializado", function () {
    var w = newWorker().worker;
    var request = {server_port: 443, interface: "any"};
    var child = scriptedChild({stdout: '{"status":"ok"}\n'});
    nextChildren.push(child);
    return invoke(w, "Post", request).then(function () {
        assert.deepStrictEqual(JSON.parse(child.written), request);
    });
});

test("status do script -> codigo HTTP", function () {
    var cases = [["invalid", 400], ["blocked", 403], ["busy", 429], ["error", 500]];
    var chain = Promise.resolve();
    cases.forEach(function (pair) {
        chain = chain.then(function () {
            var w = newWorker().worker;
            var reply = {status: pair[0], message: "m-" + pair[0]};
            nextChildren.push(scriptedChild({stdout: JSON.stringify(reply)}));
            return invoke(w, "Post", {}).then(function (op) {
                assert.strictEqual(op.statusCode, pair[1], pair[0]);
                assert.deepStrictEqual(op.body, reply);
            });
        });
    });
    return chain;
});

test("1222 bloqueada pelo script vira 403 com a mensagem original", function () {
    var w = newWorker().worker;
    var message = "Capturas na porta TCP 1222 (porta de conexão com a captura RISe) " +
        "estão desabilitadas para esta ferramenta.";
    nextChildren.push(scriptedChild({stdout: JSON.stringify({status: "blocked", message: message})}));
    return invoke(w, "Post", {node_port: 1222}).then(function (op) {
        assert.strictEqual(op.statusCode, 403);
        assert.strictEqual(op.body.message, message);
    });
});

test("saida que nao e JSON -> 500 com stderr resumido", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({stdout: "Traceback (most recent call last)", stderr: "boom\u0007", code: 1}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.strictEqual(op.body.status, "error");
        assert.ok(/codigo=1/.test(op.body.message) && /boom\?/.test(op.body.message), op.body.message);
    });
});

test("sudo sem regra -> dica de instalacao", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({stderr: "sudo: a password is required\n", code: 1}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.ok(/sudoers\.d/.test(op.body.message), op.body.message);
    });
});

test("falha ao iniciar o processo -> 500", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({error: new Error("spawn ENOENT")}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.ok(/ENOENT/.test(op.body.message));
    });
});

test("corpo invalido ou grande demais e recusado sem executar nada", function () {
    var w = newWorker().worker;
    var bodies = [null, [], "texto", 42, {pad: new Array(3000).join("x")}];
    var chain = Promise.resolve();
    bodies.forEach(function (body) {
        chain = chain.then(function () {
            return invoke(w, "Post", body).then(function (op) {
                assert.strictEqual(op.statusCode, 400);
                assert.strictEqual(op.body.status, "invalid");
            });
        });
    });
    return chain.then(function () { assert.strictEqual(spawnCalls.length, 0); });
});

test("prazo duro: SIGTERM, depois SIGKILL, resposta 504", function () {
    var made = newWorker();
    made.Worker.CONFIG.deadlineMarginSec = 0.05;
    made.Worker.CONFIG.killGraceMs = 20;
    var child = scriptedChild({hang: true});
    // um filho que ignora o SIGTERM: so fecha no SIGKILL
    child.kill = function (signal) {
        child.signals.push(signal);
        if (signal === "SIGKILL") {
            setImmediate(function () { child.emit("close", null, signal); });
        }
    };
    nextChildren.push(child);
    return invoke(made.worker, "Post", {timeout_sec: 1}).then(function (op) {
        assert.strictEqual(op.statusCode, 504);
        assert.strictEqual(op.body.status, "error");
        assert.strictEqual(child.signals[0], "SIGTERM");
        return new Promise(function (resolve) { setTimeout(resolve, 80); }).then(function () {
            assert.deepStrictEqual(child.signals, ["SIGTERM", "SIGKILL"]);
        });
    });
});

test("limite de processos simultaneos -> 429 sem iniciar outro", function () {
    var made = newWorker();
    made.Worker.CONFIG.maxInFlight = 2;
    made.Worker.CONFIG.deadlineMarginSec = 0.05;
    made.Worker.CONFIG.killGraceMs = 10;
    nextChildren.push(scriptedChild({hang: true}), scriptedChild({hang: true}));
    var a = invoke(made.worker, "Post", {timeout_sec: 1});
    var b = invoke(made.worker, "Post", {timeout_sec: 1});
    return invoke(made.worker, "Post", {}).then(function (third) {
        assert.strictEqual(third.statusCode, 429);
        assert.strictEqual(third.body.status, "busy");
        assert.strictEqual(spawnCalls.length, 2);
        return Promise.all([a, b]);
    }).then(function (done) {
        assert.strictEqual(done[0].statusCode, 504);
        // liberou as vagas: um novo pedido volta a ser aceito
        nextChildren.push(scriptedChild({stdout: '{"status":"ok"}'}));
        return invoke(made.worker, "Post", {});
    }).then(function (again) {
        assert.strictEqual(again.statusCode, 200);
    });
});

// ---- execucao ---------------------------------------------------------------------

var failures = 0;
var completed = false;

// Rede de seguranca: se o event loop esvaziar com uma promessa pendente, o Node sai
// "em silencio" com codigo 0 - isso NAO pode contar como sucesso.
process.on("exit", function () {
    if (!completed) {
        console.log("\nFALHA: a execucao terminou antes do fim dos testes " +
            "(promessa pendente / teste travado).");
        process.exitCode = 1;
    }
});

tests.reduce(function (chain, t) {
    return chain.then(function () {
        reset();
        return Promise.resolve().then(t.fn).then(function () {
            console.log("OK   " + t.name);
        }, function (err) {
            failures += 1;
            console.log("FAIL " + t.name + "\n     " + (err && err.message ? err.message : err));
        });
    });
}, Promise.resolve()).then(function () {
    completed = true;
    console.log(failures === 0
        ? "\nTODOS OS TESTES DO WORKER PASSARAM (" + tests.length + ")"
        : "\n" + failures + " TESTE(S) FALHARAM");
    process.exit(failures === 0 ? 0 : 1);
});
