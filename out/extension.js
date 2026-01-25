"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const path = require("path");
const vscode = require("vscode");
const child_process_1 = require("child_process");
const node_1 = require("vscode-languageclient/node");
let client;
let outputChannel;
let caseTerminal;
let caseTerminalWriter;
const lastReports = new Map();
const lastChangeAt = new Map();
async function activate(context) {
    const cfg = vscode.workspace.getConfiguration("xssLsp");
    const configuredPython = cfg.get("pythonPath") || "python";
    const pythonPath = resolvePythonPath(configuredPython);
    if (!pythonPath) {
        vscode.window.showErrorMessage("XSS LSP: Python executable not found. Set xssLsp.pythonPath to python3 or a full path.");
        return;
    }
    const serverMain = context.asAbsolutePath(path.join("server", "server.py"));
    const serverOptions = {
        command: pythonPath,
        args: [serverMain],
        transport: node_1.TransportKind.stdio,
        options: {
            cwd: context.asAbsolutePath("server"),
        },
    };
    const clientOptions = {
        documentSelector: [{ scheme: "file", language: "python" }],
        // 타이핑이 많아도 부드럽게 하려면 client 측에서 sync/diagnostic 호출이 늘어나므로
        // 서버는 SyntaxError시 조용히 무시하는 방식으로 "실시간" UX 유지
    };
    client = new node_1.LanguageClient("xssLsp", "XSS LSP (Python AST)", serverOptions, clientOptions);
    outputChannel = vscode.window.createOutputChannel("XSS LSP Issues");
    context.subscriptions.push(outputChannel);
    context.subscriptions.push(vscode.window.onDidCloseTerminal((terminal) => {
        if (terminal === caseTerminal) {
            caseTerminal = undefined;
            if (caseTerminalWriter) {
                caseTerminalWriter.dispose();
                caseTerminalWriter = undefined;
            }
        }
    }));
    context.subscriptions.push(vscode.languages.onDidChangeDiagnostics((event) => {
        void reportXssDiagnostics(event.uris);
    }));
    context.subscriptions.push(vscode.workspace.onDidChangeTextDocument((event) => {
        if (event.document.languageId === "python") {
            lastChangeAt.set(event.document.uri.toString(), Date.now());
        }
    }), vscode.workspace.onDidSaveTextDocument((doc) => {
        if (doc.languageId === "python") {
            lastChangeAt.set(doc.uri.toString(), Date.now());
        }
    }), vscode.workspace.onDidOpenTextDocument((doc) => {
        if (doc.languageId === "python") {
            lastChangeAt.set(doc.uri.toString(), Date.now());
        }
    }));
    const started = client.start();
    // start()가 Disposable을 반환하는 경우
    if (typeof started?.dispose === "function") {
        context.subscriptions.push(started);
    }
    else {
        // start()가 Promise를 반환하는 경우 (구버전 호환)
        started.then(() => { }).catch(() => { });
    }
    vscode.window.showInformationMessage("XSS LSP started (Python AST).");
}
async function deactivate() {
    if (client) {
        await client.stop();
        client = undefined;
    }
}
function resolvePythonPath(configured) {
    const candidates = [configured, "python3", "python"];
    for (const candidate of candidates) {
        if (!candidate) {
            continue;
        }
        const result = (0, child_process_1.spawnSync)(candidate, ["--version"], { stdio: "ignore" });
        if (!result.error && result.status === 0) {
            return candidate;
        }
    }
    return undefined;
}
async function reportXssDiagnostics(uris) {
    if (!outputChannel) {
        return;
    }
    let shown = false;
    let terminalShown = false;
    for (const uri of uris) {
        const uriKey = uri.toString();
        const doc = await vscode.workspace.openTextDocument(uri);
        const diagnostics = vscode.languages
            .getDiagnostics(uri)
            .filter((diag) => diag.source === "xss-lsp");
        const cases = extractCases(doc);
        if (cases.length > 0) {
            const elapsedMs = Date.now() - (lastChangeAt.get(uriKey) ?? Date.now());
            const elapsedSec = Math.max(0, elapsedMs) / 1000;
            const reportKey = cases
                .map((c) => `${c.id}:${caseHasIssue(diagnostics, c) ? 1 : 0}`)
                .join("|");
            if (reportKey === lastReports.get(uriKey)) {
                continue;
            }
            lastReports.set(uriKey, reportKey);
            if (!shown) {
                outputChannel.show(true);
                shown = true;
            }
            const { terminal, writer } = getCaseTerminal();
            if (!terminalShown) {
                terminal.show(true);
                terminalShown = true;
            }
            for (const c of cases) {
                const ok = caseHasIssue(diagnostics, c);
                const status = ok ? "성공" : "실패";
                const line = `### ${c.id}번 케이스 -> ${status} ${elapsedSec.toFixed(2)}s`;
                outputChannel.appendLine(line);
                writer.fire(`${line}\r\n`);
            }
            continue;
        }
        if (diagnostics.length === 0) {
            continue;
        }
        const fingerprint = diagnostics
            .map((diag) => {
            const { start, end } = diag.range;
            return `${start.line}:${start.character}:${end.line}:${end.character}:${diag.message}`;
        })
            .sort()
            .join("|");
        if (fingerprint === lastReports.get(uriKey)) {
            continue;
        }
        lastReports.set(uriKey, fingerprint);
        if (!shown) {
            outputChannel.show(true);
            shown = true;
        }
        for (const diag of diagnostics) {
            const line = diag.range.start.line;
            const col = diag.range.start.character;
            const lineText = doc.lineAt(line).text;
            outputChannel.appendLine(`[XSS] ${path.basename(uri.fsPath)}:${line + 1}:${col + 1} ${diag.message}`);
            outputChannel.appendLine(lineText);
        }
    }
}
function getCaseTerminal() {
    if (caseTerminal && caseTerminalWriter) {
        return { terminal: caseTerminal, writer: caseTerminalWriter };
    }
    const writeEmitter = new vscode.EventEmitter();
    const pty = {
        onDidWrite: writeEmitter.event,
        open: () => { },
        close: () => { },
    };
    const terminal = vscode.window.createTerminal({
        name: "XSS LSP Cases",
        pty,
    });
    caseTerminal = terminal;
    caseTerminalWriter = writeEmitter;
    return { terminal, writer: writeEmitter };
}
function extractCases(doc) {
    const cases = [];
    for (let i = 0; i < doc.lineCount; i++) {
        const text = doc.lineAt(i).text;
        const match = text.match(/^\s*#\s*CASE\s*(\d+)\b/i);
        if (match) {
            cases.push({
                id: Number(match[1]),
                startLine: i,
                endLine: doc.lineCount - 1,
            });
        }
    }
    for (let i = 0; i < cases.length - 1; i++) {
        cases[i].endLine = cases[i + 1].startLine - 1;
    }
    return cases;
}
function caseHasIssue(diagnostics, caseRange) {
    return diagnostics.some((diag) => {
        const line = diag.range.start.line;
        return line >= caseRange.startLine && line <= caseRange.endLine;
    });
}
//# sourceMappingURL=extension.js.map