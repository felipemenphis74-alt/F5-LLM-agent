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
    // captura "longa": so termina quando o teste chama child.finishWith(objeto)
    child.finishWith = function (obj, code) {
        child.stdout.emit("data", Buffer.from(JSON.stringify(obj) + "\n"));
        child.emit("close", code === undefined ? 0 : code, null);
    };
    child.stdin.end = function (data) {
        child.written = data;
        if (spec.hang || spec.manual) {
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
    worker.logged = [];
    worker.logger = {
        info: function (m) { worker.logged.push(m); },
        error: function (m) { worker.logged.push(m); },
        warning: function (m) { worker.logged.push(m); }
    };
    return {worker: worker, Worker: Worker};
}

var BASE_URI = "/shared/f5_tcpdump";

function invoke(worker, method, body, query) {
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
            getUri: function () { return {pathname: BASE_URI, query: query === undefined ? {} : query}; },
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

var INTERNALS = /sudo|sudoers|restnoded|stderr|stdout|traceback|ENOENT|spawn|codigo=|\/usr|\/shared|script|processo|worker|bytes/i;

test("saida que nao e JSON -> 500 GENERICO; o detalhe so vai para o log interno", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({stdout: "Traceback (most recent call last)", stderr: "boom\u0007", code: 1}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.deepStrictEqual(op.body, {status: "error",
            message: "A captura não pôde ser concluída. Tente novamente em alguns minutos."});
        assert.ok(!INTERNALS.test(JSON.stringify(op.body)), JSON.stringify(op.body));
        assert.ok(w.logged.some(function (l) { return /codigo=1/.test(l) && /boom\?/.test(l); }),
            "o detalhe deve ir para o log: " + w.logged.join(" | "));
    });
});

test("sudo sem regra -> 500 generico (a dica de instalacao fica no log)", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({stderr: "sudo: a password is required\n", code: 1}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.ok(!INTERNALS.test(JSON.stringify(op.body)), JSON.stringify(op.body));
        assert.ok(w.logged.some(function (l) { return /sudoers\.d/.test(l); }), w.logged.join("|"));
    });
});

test("falha ao iniciar o processo -> 500 generico", function () {
    var w = newWorker().worker;
    nextChildren.push(scriptedChild({error: new Error("spawn ENOENT")}));
    return invoke(w, "Post", {}).then(function (op) {
        assert.strictEqual(op.statusCode, 500);
        assert.deepStrictEqual(op.body, {status: "error",
            message: "A captura não está disponível no momento."});
        assert.ok(w.logged.some(function (l) { return /ENOENT/.test(l); }), w.logged.join("|"));
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
    made.Worker.CONFIG.fastWindowMs = 5000;     // POST sincrono: espera o prazo estourar
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
        assert.ok(!INTERNALS.test(JSON.stringify(op.body)), JSON.stringify(op.body));
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
    made.Worker.CONFIG.fastWindowMs = 5000;
    nextChildren.push(scriptedChild({hang: true}), scriptedChild({hang: true}));
    var a = invoke(made.worker, "Post", {timeout_sec: 1});
    var b = invoke(made.worker, "Post", {timeout_sec: 1});
    return invoke(made.worker, "Post", {}).then(function (third) {
        assert.strictEqual(third.statusCode, 429);
        assert.strictEqual(third.body.status, "busy");
        assert.ok(!INTERNALS.test(JSON.stringify(third.body)), JSON.stringify(third.body));
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

// ---- modo assincrono (capturas que passam do ~60 s do restjavad) -----------------------

function asyncWorker(overrides) {
    var made = newWorker();
    made.Worker.CONFIG.fastWindowMs = 15;
    Object.keys(overrides || {}).forEach(function (key) {
        made.Worker.CONFIG[key] = overrides[key];
    });
    return made.worker;
}

function startLong(w, request) {
    var child = scriptedChild({manual: true});
    nextChildren.push(child);
    return invoke(w, "Post", request || {timeout_sec: 180}).then(function (op) {
        return {op: op, child: child};
    });
}

function poll(w, id) {
    return invoke(w, "Get", null, {job_id: id});
}

function nextTick() {
    return new Promise(function (resolve) { setTimeout(resolve, 5); });
}

test("captura longa: POST devolve 202 + job_id e GET acompanha ate o resultado", function () {
    var w = asyncWorker();
    var started;
    var id;
    return startLong(w).then(function (s) {
        started = s;
        assert.strictEqual(s.op.statusCode, 202);
        assert.strictEqual(s.op.body.status, "running");
        assert.ok(/^[0-9a-f]{32}$/.test(s.op.body.job_id), s.op.body.job_id);
        id = s.op.body.job_id;
        assert.strictEqual(s.op.body.poll, "/mgmt/shared/f5_tcpdump?job_id=" + id);
        assert.strictEqual(w.inFlight, 1);
        return poll(w, id);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 202);
        assert.strictEqual(op.body.status, "running");
        assert.strictEqual(op.body.job_id, id);
        var reply = {status: "ok", exit_status: 124, summary: {total_packets: 7}, packets: []};
        started.child.finishWith(reply);
        return nextTick().then(function () {
            return poll(w, id);
        }).then(function (done) {
            assert.strictEqual(done.statusCode, 200);
            assert.strictEqual(done.body.status, "ok");
            assert.strictEqual(done.body.job_id, id);
            assert.deepStrictEqual(done.body.summary, reply.summary);
            assert.ok(done.body.started_at && done.body.finished_at);
            assert.strictEqual(w.inFlight, 0);
            // o resultado continua consultavel (nao e "consumido" pela leitura)
            return poll(w, id);
        });
    }).then(function (again) {
        assert.strictEqual(again.statusCode, 200);
        assert.strictEqual(again.body.job_id, id);
    });
});

test("job_id tambem e aceito com query em string e em lista", function () {
    var w = asyncWorker();
    var id;
    return startLong(w).then(function (s) {
        id = s.op.body.job_id;
        return invoke(w, "Get", null, "job_id=" + id);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 202);
        return invoke(w, "Get", null, {job_id: [id, "outro"]});
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 202);
        assert.strictEqual(op.body.job_id, id);
    });
});

test("o mapeamento de status do resultado assincrono e o mesmo do POST", function () {
    var cases = [["error", 500], ["busy", 429], ["blocked", 403], ["invalid", 400]];
    var chain = Promise.resolve();
    cases.forEach(function (pair) {
        chain = chain.then(function () {
            var w = asyncWorker();
            return startLong(w).then(function (s) {
                s.child.finishWith({status: pair[0], message: "m"});
                return nextTick().then(function () {
                    return poll(w, s.op.body.job_id);
                });
            }).then(function (op) {
                assert.strictEqual(op.statusCode, pair[1], pair[0]);
                assert.strictEqual(op.body.status, pair[0]);
            });
        });
    });
    return chain;
});

test("resposta rapida (busy/invalid) continua sincrona e nao deixa job guardado", function () {
    var w = asyncWorker({fastWindowMs: 5000});
    nextChildren.push(scriptedChild({stdout: JSON.stringify({status: "busy", message: "m"})}));
    return invoke(w, "Post", {timeout_sec: 5}).then(function (op) {
        assert.strictEqual(op.statusCode, 429);
        assert.strictEqual(op.body.job_id, undefined);
        return invoke(w, "Get");
    }).then(function (info) {
        assert.strictEqual(info.statusCode, 200);
        assert.strictEqual(Object.keys(w.jobs).length, 0);   // nenhum job guardado
        // a interface de captura e o modo verbose nao existem para o cliente
        assert.ok(info.body.fields.indexOf("interface") === -1, info.body.fields);
        assert.ok(info.body.fields.indexOf("verbose") === -1, info.body.fields);
        assert.ok(info.body.fields.indexOf("detalhes") !== -1, info.body.fields);
        assert.strictEqual(info.body.async.max_timeout_sec, 180);
        // o descritor nao expoe estado interno do worker nem a mecanica
        assert.strictEqual(info.body.jobs, undefined);
        assert.strictEqual(info.body.async.fast_window_ms, undefined);
        assert.ok(!INTERNALS.test(JSON.stringify(info.body.description)), info.body.description);
    });
});

test("id desconhecido -> 404, id malformado ou vazio -> 400, nada e executado", function () {
    var w = asyncWorker();
    return poll(w, new Array(33).join("a")).then(function (op) {
        assert.strictEqual(op.statusCode, 404);
        assert.strictEqual(op.body.status, "not_found");
        assert.ok(!INTERNALS.test(JSON.stringify(op.body)), JSON.stringify(op.body));
        return poll(w, "../etc/passwd");
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 400);
        return poll(w, "");
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 400);
        return poll(w, new Array(33).join("A"));      // so hexa minusculo
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 400);
        assert.strictEqual(spawnCalls.length, 0);
    });
});

test("resultado expira depois do TTL", function () {
    var w = asyncWorker({jobTtlSec: 0.02});
    var id;
    return startLong(w).then(function (s) {
        id = s.op.body.job_id;
        s.child.finishWith({status: "ok"});
        return nextTick();
    }).then(function () {
        return poll(w, id);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 200);
        return new Promise(function (resolve) { setTimeout(resolve, 40); });
    }).then(function () {
        return poll(w, id);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 404);
    });
});

test("maxJobs: guarda so os concluidos mais recentes", function () {
    var w = asyncWorker({maxJobs: 2, maxInFlight: 10});
    var ids = [];
    var chain = Promise.resolve();
    [0, 1, 2, 3].forEach(function (n) {
        chain = chain.then(function () {
            return startLong(w).then(function (s) {
                ids.push(s.op.body.job_id);
                return new Promise(function (resolve) { setTimeout(resolve, 3); }).then(function () {
                    s.child.finishWith({status: "ok", n: n});
                });
            });
        });
    });
    return chain.then(function () {
        return invoke(w, "Get");     // dispara a limpeza
    }).then(function (info) {
        assert.strictEqual(Object.keys(w.jobs).length, 2);   // so os 2 concluidos mais novos
        return poll(w, ids[0]);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 404);
        return poll(w, ids[3]);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 200);
        assert.strictEqual(op.body.n, 3);
    });
});

test("prazo duro de job assincrono: 504 consultavel e vaga liberada", function () {
    var w = asyncWorker({deadlineMarginSec: 0.05, killGraceMs: 10});
    var child = scriptedChild({manual: true});
    nextChildren.push(child);
    var id;
    return invoke(w, "Post", {timeout_sec: 1}).then(function (op) {
        assert.strictEqual(op.statusCode, 202);
        id = op.body.job_id;
        return new Promise(function (resolve) { setTimeout(resolve, 1200); });
    }).then(function () {
        return poll(w, id);
    }).then(function (op) {
        assert.strictEqual(op.statusCode, 504);
        assert.strictEqual(op.body.status, "error");
        assert.strictEqual(child.signals[0], "SIGTERM");
        assert.strictEqual(w.inFlight, 0);
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
