/*
 * f5TcpdumpWorker.js - extensao iControl LX que expoe o f5_tcpdump.py por REST.
 *
 *   POST /mgmt/shared/f5_tcpdump   corpo JSON: interface, server_port, node_port,
 *                                  host, count, timeout_sec   (todos opcionais)
 *   GET  /mgmt/shared/f5_tcpdump   descricao do endpoint (nao executa nada)
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

var CONFIG = {
    sudoPath: "/usr/bin/sudo",
    scriptPath: "/shared/f5_tcpdump/f5_tcpdump.py",
    maxBodyBytes: 2048,
    maxOutputBytes: 4 * 1024 * 1024,
    maxStderrBytes: 4096,
    maxInFlight: 4,            // processos simultaneos deste worker
    defaultTimeoutSec: 20,     // espelha o f5_tcpdump.py
    maxTimeoutSec: 60,
    deadlineMarginSec: 15,     // folga alem do timeout_sec do pedido
    killGraceMs: 3000
};

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
    this._reply(restOperation, 200, {
        name: "f5_tcpdump",
        description: "Captura tcpdump segura + parsing ISO 8583 (somente leitura)",
        usage: "POST neste mesmo caminho com um objeto JSON",
        fields: ["interface", "server_port", "node_port", "host", "count", "timeout_sec"],
        status_values: Object.keys(HTTP_BY_STATUS),
        http_status: HTTP_BY_STATUS
    });
};

F5TcpdumpWorker.prototype.onPost = function (restOperation) {
    var self = this;
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
            message: "Muitas capturas em andamento neste worker; tente novamente em instantes.",
            retry_after_minutes: 1
        });
        return;
    }

    self.inFlight += 1;
    self._log("info", "pedido: " + payload);

    runScript(payload, deadlineMs(body), function (result, httpOverride) {
        self.inFlight -= 1;
        var httpStatus = httpOverride || HTTP_BY_STATUS[result.status] || 500;
        self._log("info", "resultado: status=" + result.status + " http=" + httpStatus);
        self._reply(restOperation, httpStatus, result);
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
function runScript(payload, limitMs, callback) {
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
        finish(errorResult("Prazo excedido (" + Math.round(limitMs / 1000) +
            " s) aguardando o script."), 504);
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
        finish(errorResult("Falha ao iniciar o script: " + err.message));
        return;
    }

    child.on("error", function (err) {
        finish(errorResult("Falha ao iniciar o script: " + err.message));
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
            finish(errorResult("Saida do script acima de " + CONFIG.maxOutputBytes + " bytes."));
            return;
        }
        var parsed = parseResult(stdout);
        if (parsed) {
            finish(parsed);
            return;
        }
        var detail = tail(stderr, 300);
        finish(errorResult("Saida inesperada do script (codigo=" + code +
            (signal ? ", sinal=" + signal : "") + ")." + (detail ? " stderr: " + detail : "") +
            sudoHint(stderr)));
    });

    child.stdin.on("error", function () { /* EPIPE se o filho morrer antes de ler */ });
    child.stdin.end(payload);
}

module.exports = F5TcpdumpWorker;
