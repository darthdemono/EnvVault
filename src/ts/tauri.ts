/** Minimal typed boundary for Tauri's runtime-injected IPC bridge. */
type Invoke = (command: string, args?: unknown) => Promise<unknown>;

type TauriRuntime = { core?: { invoke?: Invoke } };

function currentInvoke(): Invoke | undefined {
  return (window as Window & { __TAURI__?: TauriRuntime }).__TAURI__?.core?.invoke;
}

/** Read the runtime at call time; tests, hot reload and late webview injection can replace it. */
export function isTauri(): boolean {
  return currentInvoke() !== undefined;
}

export const inTauri = isTauri();

export async function invokeTauri<T>(command: string, args?: unknown): Promise<T> {
  const invoke = currentInvoke();
  if (!invoke) throw new Error('Tauri IPC is unavailable');
  return invoke(command, args) as Promise<T>;
}
