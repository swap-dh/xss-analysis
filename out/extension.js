"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const path = require("path");
const vscode = require("vscode");
const node_1 = require("vscode-languageclient/node");
let client;
async function activate(context) {
    const cfg = vscode.workspace.getConfiguration("xssLsp");
    const pythonPath = cfg.get("pythonPath") || "python";
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
//# sourceMappingURL=extension.js.map