import * as path from "path";
import * as vscode from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;

export async function activate(context: vscode.ExtensionContext) {
  const cfg = vscode.workspace.getConfiguration("xssLsp");
  const pythonPath = cfg.get<string>("pythonPath") || "python";

  const serverMain = context.asAbsolutePath(path.join("server", "server.py"));

  const serverOptions: ServerOptions = {
    command: pythonPath,
    args: [serverMain],
    transport: TransportKind.stdio,
    options: {
      cwd: context.asAbsolutePath("server"),
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "python" }],
    // 타이핑이 많아도 부드럽게 하려면 client 측에서 sync/diagnostic 호출이 늘어나므로
    // 서버는 SyntaxError시 조용히 무시하는 방식으로 "실시간" UX 유지
  };

  client = new LanguageClient(
    "xssLsp",
    "XSS LSP (Python AST)",
    serverOptions,
    clientOptions
  );

  const started = client.start();

// start()가 Disposable을 반환하는 경우
if (typeof (started as any)?.dispose === "function") {
  context.subscriptions.push(started as any);
} else {
  // start()가 Promise를 반환하는 경우 (구버전 호환)
  started.then(() => {}).catch(() => {});
}


  vscode.window.showInformationMessage("XSS LSP started (Python AST).");
}

export async function deactivate() {
  if (client) {
    await client.stop();
    client = undefined;
  }
}
