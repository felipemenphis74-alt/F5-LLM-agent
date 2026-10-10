/*
 * f5TcpdumpWorker.js - extensao iControl LX que expoe o f5_tcpdump.py por REST.
 *
 *   POST /mgmt/shared/f5_tcpdump                 corpo JSON: interface, server_port,
 *                                                node_port, host, count, timeout_sec
 *                                                (todos opcionais)
 *   GET  /mgmt/shared/f5_tcpdump                 descricao do endpoint (nao executa nada)
 *   GET  /mgmt/shared/f5_tcpdump?job_id=<id>     consulta uma captura iniciada pelo POST
 *
 * (O id vai em query string porque o restjavad so encaminha ao worker o caminho exato
 * registrado - /shared/f5_tcpdump/<id> volta 404 "Public URI path not registered".)
 *
 * ASSINCRONO: o gateway REST do BIG-IP (restjavad) interrompe - e REENVIA - POSTs que
 * passam de ~60 s, e as capturas podem chegar a 180 s. Por isso o POST espera so
 * `fastWindowMs`: se o script terminou (invalid/blocked/busy/erro ou captura curta), a
 * resposta e a mesma de sempre (200/400/403/429/500). Se a captura segue rodando, o
 * POST devolve 202 com `job_id` e o resultado sai por GET ?job_id=<id>:
 *     202  status "running"  (captura em andamento)
 *     200/4xx/5xx            o mesmo JSON e o mesmo mapeamento de status do POST
 *     404                    id desconhecido (expirou ou o restnoded reiniciou)
 * Os jobs ficam so em memoria deste worker (jobTtlSec depois de terminar).
 *
 * Este arquivo e so a camada de transporte. A VALIDACAO e a SAFETY (porta 1222,
 * limites, trava de concorrencia) vivem no f5_tcpdump.py, que e a autoridade - aqui
 * so repassamos o JSON por stdin e devolvemos o JSON de saida.
 *
 * O worker roda como o usuario `restnoded` (sem privilegio de root); o script e
 * chamado via `sudo -n <script>`, por uma regra unica de /etc/sudoers.d (ver
 * onbox/deploy/f5_tcpdump.sudoers). Nada de shell: argv fixo, pedido por stdin.
 *
 * Compativel com o Node do iControl LX do BIG-IP 17.0 (v8.11) - sem async/await.
 */
"use strict";

var childProcess = require("child_process");
var crypto = require("crypto");
var querystring = require("querystring");

var CONFIG = {
    sudoPath: "/usr/bin/sudo",
    scriptPath: "/shared/f5_tcpdump/f5_tcpdump.py",
    maxBodyBytes: 2048,
    maxOutputBytes: 4 * 1024 * 1024,
    maxStderrBytes: 4096,
    maxInFlight: 4,            // processos simultaneos deste worker
    defaultTimeoutSec: 20,     // espelha o f5_tcpdump.py
    maxTimeoutSec: 180,        // espelha MAX_TIMEOUT_SEC do f5_tcpdump.py
    deadlineMarginSec: 15,     // folga alem do timeout_sec do pedido
    killGraceMs: 3000,
    fastWindowMs: 2000,        // quanto o POST espera antes de virar 202 + job
    jobTtlSec: 900,            // quanto tempo o resultado fica consultavel
    maxJobs: 50                // jobs guardados (concluidos mais antigos saem primeiro)
};

// Mensagens que chegam ao cliente da API: nenhuma cita metodo, comando, usuario do worker,
// regra de sudo, stderr ou texto vindo do equipamento (o detalhe vai para o log interno).
var MSG = {
    unavailable: "A captura não está disponível no momento.",
    failed: "A captura não pôde ser concluída. Tente novamente em alguns minutos.",
    timeout: "A captura excedeu o tempo máximo. Tente novamente com uma janela menor.",
    busy: "Há capturas demais em andamento; tente novamente em instantes.",
    notFound: "Captura desconhecida ou expirada.",
    tooBig: "O resultado da captura é grande demais. Reduza a janela ou o filtro."
};

var JOB_ID_RE = /^[0-9a-f]{32}$/;
var BASE_PATH = "/mgmt/shared/f5_tcpdump";

// status devolvido pelo script -> codigo HTTP
var HTTP_BY_STATUS = {
    ok: 200,
    invalid: 400,
    blocked: 403,
    busy: 429,
    error: 500
};

function F5TcpdumpWorker() {
    this.state = {};
    this.inFlight = 0;
    this.jobs = {};            // job_id -> {id, state, createdAt, finishedAt, result, http}
}

F5TcpdumpWorker.prototype.WORKER_URI_PATH = "shared/f5_tcpdump";
F5TcpdumpWorker.prototype.isPublic = true;
F5TcpdumpWorker.prototype.isSingleton = true;
F5TcpdumpWorker.CONFIG = CONFIG;

F5TcpdumpWorker.prototype.onStart = function (success) {
    this._log("info", "f5_tcpdump worker iniciado (script: " + CONFIG.scriptPath + ")");
    success();
};

F5TcpdumpWorker.prototype.onGet = function (restOperation) {
    var jobId = jobIdParam(restOperation);
    if (jobId !== null) {
        this._getJob(restOperation, jobId);
        return;
    }
    this._purgeJobs();
    this._reply(restOperation, 200, {
        name: "f5_tcpdump",
        description: "Validação de tráfego de uma VS (somente leitura)",
        usage: "POST neste caminho com um objeto JSON; se a captura demorar, a resposta " +
            "e 202 com job_id e o resultado sai em GET " + BASE_PATH + "?job_id=<job_id>",
        fields: ["server_port", "node_port", "host", "count", "timeout_sec", "vs_addr",
            "client_addr", "node_addr", "detalhes", "stan"],
        status_values: Object.keys(HTTP_BY_STATUS),
        http_status: HTTP_BY_STATUS,
        async: {
            accepted_http: 202,
            running_status: "running",
            result_ttl_sec: CONFIG.jobTtlSec,
            max_timeout_sec: CONFIG.maxTimeoutSec
        },
    });
};

F5TcpdumpWorker.prototype._getJob = function (restOperation, id) {
    this._purgeJobs();
    if (!JOB_ID_RE.test(id)) {
        this._reply(restOperation, 400, {status: "invalid", message: "job_id invalido."});
        return;
    }
    var job = this.jobs[id];
    if (!job) {
        this._reply(restOperation, 404, {
            status: "not_found",
            message: MSG.notFound,
            job_id: id
        });
        return;
    }
    if (job.state === "running") {
        this._reply(restOperation, 202, this._runningBody(job));
        return;
    }
    this._reply(restOperation, job.http, withJob(job.result, job));
};

F5TcpdumpWorker.prototype._runningBody = function (job) {
    return {
        status: "running",
        job_id: job.id,
        started_at: new Date(job.createdAt).toISOString(),
        elapsed_sec: Math.round((Date.now() - job.createdAt) / 100) / 10,
        max_sec: Math.round(job.limitMs / 1000),
        poll: BASE_PATH + "?job_id=" + job.id,
        message: "Captura em andamento; consulte GET " + BASE_PATH + "?job_id=" + job.id + "."
    };
};

// Remove resultados expirados e, se passar de maxJobs, os concluidos mais antigos.
F5TcpdumpWorker.prototype._purgeJobs = function () {
    var now = Date.now();
    var ttlMs = CONFIG.jobTtlSec * 1000;
    var jobs = this.jobs;
    var done = [];
    Object.keys(jobs).forEach(function (id) {
        var job = jobs[id];
        if (job.state !== "done") {
            return;
        }
        if (now - job.finishedAt > ttlMs) {
            delete jobs[id];
        } else {
            done.push(job);
        }
    });
    var excess = Object.keys(jobs).length - CONFIG.maxJobs;
    if (excess > 0) {
        done.sort(function (a, b) { return a.finishedAt - b.finishedAt; });
        done.slice(0, excess).forEach(function (job) { delete jobs[job.id]; });
    }
};

F5TcpdumpWorker.prototype.onPost = function (restOperation) {
    var self = this;
    self._purgeJobs();
    var body = restOperation.getBody();

    if (body === null || typeof body !== "object" || Array.isArray(body)) {
        self._reply(restOperation, 400, {
            status: "invalid",
            message: "O corpo deve ser um objeto JSON."
        });
        return;
    }

    var payload;
    try {
        payload = JSON.stringify(body);
    } catch (err) {
        self._reply(restOperation, 400, {status: "invalid", message: "Corpo nao serializavel."});
        return;
    }
    if (Buffer.byteLength(payload, "utf8") > CONFIG.maxBodyBytes) {
        self._reply(restOperation, 400, {
            status: "invalid",
            message: "Corpo acima do limite de " + CONFIG.maxBodyBytes + " bytes."
        });
        return;
    }

    if (self.inFlight >= CONFIG.maxInFlight) {
        self._reply(restOperation, 429, {
            status: "busy",
            message: MSG.busy,
            retry_after_minutes: 1
        });
        return;
    }

    var limitMs = deadlineMs(body);
    var job = {
        id: crypto.randomBytes(16).toString("hex"),
        state: "running",
        createdAt: Date.now(),
        finishedAt: null,
        limitMs: limitMs,
        result: null,
        http: null
    };
    self.jobs[job.id] = job;
    self.inFlight += 1;
    self._log("info", "pedido " + job.id + ": " + payload);

    var replied = false;
    var fastTimer = setTimeout(function () {
        // a captura segue rodando: libera o POST (antes do ~60 s do restjavad) com o id
        if (!replied) {
            replied = true;
            self._reply(restOperation, 202, self._runningBody(job));
        }
    }, CONFIG.fastWindowMs);

    runScript(payload, limitMs, function (detail) {
        self._log("warning", detail);     // so no log interno do restnoded
    }, function (result, httpOverride) {
        self.inFlight -= 1;
        var httpStatus = httpOverride || HTTP_BY_STATUS[result.status] || 500;
        job.state = "done";
        job.finishedAt = Date.now();
        job.result = result;
        job.http = httpStatus;
        self._log("info", "resultado " + job.id + ": status=" + result.status +
            " http=" + httpStatus + " em " +
            Math.round((job.finishedAt - job.createdAt) / 100) / 10 + " s");
        if (!replied) {
            // terminou dentro da janela rapida: resposta sincrona, nada a consultar depois
            replied = true;
            clearTimeout(fastTimer);
            delete self.jobs[job.id];
            self._reply(restOperation, httpStatus, result);
        }
    });
};

F5TcpdumpWorker.prototype._reply = function (restOperation, httpStatus, body) {
    restOperation.setStatusCode(httpStatus);
    restOperation.setContentType("application/json");
    restOperation.setBody(body);
    this.completeRestOperation(restOperation);
};

F5TcpdumpWorker.prototype._log = function (level, message) {
    var logger = this.logger;
    if (logger && typeof logger[level] === "function") {
        logger[level]("[f5_tcpdump] " + message);
    }
};

// ---------------------------------------------------------------------------

// Valor de ?job_id=... (string) ou null se o parametro nao veio. O formato do `query`
// varia (objeto ja parseado ou string), entao aceita os dois e tambem `search`/`path`.
function jobIdParam(restOperation) {
    var uri = typeof restOperation.getUri === "function" ? restOperation.getUri() : null;
    if (!uri || typeof uri !== "object") {
        return null;
    }
    var query = uri.query;
    if (typeof query === "string") {
        query = querystring.parse(query.replace(/^\?/, ""));
    }
    if (!query || typeof query !== "object") {
        var raw = typeof uri.search === "string" ? uri.search :
            (typeof uri.path === "string" && uri.path.indexOf("?") !== -1 ?
                uri.path.slice(uri.path.indexOf("?")) : "");
        query = querystring.parse(raw.replace(/^\?/, ""));
    }
    var value = query.job_id;
    if (Array.isArray(value)) {
        value = value[0];
    }
    return typeof value === "string" ? value : null;
}

// resultado + identificacao do job (so nas respostas que vem de um job assincrono)
function withJob(result, job) {
    var out = {};
    Object.keys(result).forEach(function (key) { out[key] = result[key]; });
    out.job_id = job.id;
    out.started_at = new Date(job.createdAt).toISOString();
    out.finished_at = new Date(job.finishedAt).toISOString();
    return out;
}

function deadlineMs(body) {
    var timeout = CONFIG.defaultTimeoutSec;
    if (typeof body.timeout_sec === "number" && isFinite(body.timeout_sec) &&
        body.timeout_sec >= 1) {
        timeout = Math.min(body.timeout_sec, CONFIG.maxTimeoutSec);
    }
    return (timeout + CONFIG.deadlineMarginSec) * 1000;
}

function errorResult(message) {
    return {status: "error", message: message};
}

function tail(text, limit) {
    // so ASCII imprimivel e quebras - nada de controle vindo do stderr
    var clean = String(text).replace(/[^\x20-\x7e\n]/g, "?").trim();
    return clean.length > limit ? clean.slice(clean.length - limit) : clean;
}

function parseResult(stdout) {
    var lines = stdout.split("\n").filter(function (line) { return line.trim() !== ""; });
    if (lines.length === 0) {
        return null;
    }
    try {
        var parsed = JSON.parse(lines[lines.length - 1]);
        if (parsed && typeof parsed === "object" && typeof parsed.status === "string") {
            return parsed;
        }
    } catch (err) {
        return null;
    }
    return null;
}

function sudoHint(stderr) {
    if (/password is required|not in the sudoers|may not run sudo|no tty present/i.test(stderr)) {
        return " Sem permissao de sudo para o usuario do worker (restnoded): instale a " +
            "regra de /etc/sudoers.d (onbox/deploy/f5_tcpdump.sudoers).";
    }
    return "";
}

/*
 * Executa `sudo -n <script>` com o pedido em stdin. Chama callback(resultado[, http])
 * exatamente uma vez. Prazo duro: timeout_sec + margem; ao estourar manda SIGTERM
 * (o sudo repassa ao script) e depois SIGKILL.
 */
function runScript(payload, limitMs, detailLog, callback) {
    var finished = false;
    var stdout = "";
    var stderr = "";
    var outBytes = 0;
    var tooBig = false;
    var killTimer = null;
    var child;

    var deadline = setTimeout(function () {
        try {
            child.kill("SIGTERM");
        } catch (err) { /* ja terminou */ }
        killTimer = setTimeout(function () {
            try {
                child.kill("SIGKILL");
            } catch (err) { /* ja terminou */ }
        }, CONFIG.killGraceMs);
        detailLog("prazo excedido (" + Math.round(limitMs / 1000) + " s) aguardando o script");
        finish(errorResult(MSG.timeout), 504);
    }, limitMs);

    function finish(result, httpOverride) {
        if (finished) {
            return;
        }
        finished = true;
        clearTimeout(deadline);
        callback(result, httpOverride);
    }

    try {
        child = childProcess.spawn(CONFIG.sudoPath, ["-n", CONFIG.scriptPath],
            {stdio: ["pipe", "pipe", "pipe"]});
    } catch (err) {
        detailLog("falha ao iniciar o script: " + err.message);
        finish(errorResult(MSG.unavailable));
        return;
    }

    child.on("error", function (err) {
        detailLog("falha ao iniciar o script: " + err.message);
        finish(errorResult(MSG.unavailable));
    });

    child.stdout.on("data", function (chunk) {
        outBytes += chunk.length;
        if (outBytes > CONFIG.maxOutputBytes) {
            tooBig = true;
            try {
                child.kill("SIGTERM");
            } catch (err) { /* ja terminou */ }
            return;
        }
        stdout += chunk.toString("utf8");
    });

    child.stderr.on("data", function (chunk) {
        if (stderr.length < CONFIG.maxStderrBytes) {
            stderr += chunk.toString("utf8");
        }
    });

    child.on("close", function (code, signal) {
        if (killTimer) {
            clearTimeout(killTimer);
        }
        if (tooBig) {
            detailLog("saida do script acima de " + CONFIG.maxOutputBytes + " bytes");
            finish(errorResult(MSG.tooBig));
            return;
        }
        var parsed = parseResult(stdout);
        if (parsed) {
            finish(parsed);
            return;
        }
        var detail = tail(stderr, 300);
        detailLog("saida inesperada do script (codigo=" + code +
            (signal ? ", sinal=" + signal : "") + ")" + (detail ? " stderr: " + detail : "") +
            sudoHint(stderr));
        finish(errorResult(MSG.failed));
    });

    child.stdin.on("error", function () { /* EPIPE se o filho morrer antes de ler */ });
    child.stdin.end(payload);
}

module.exports = F5TcpdumpWorker;
