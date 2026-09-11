# Workspace browser transport evaluation

## Decision

Keep noVNC as the supported transport while evaluating KasmVNC and Xpra HTML5
in separate experimental workspace images. A browser desktop will always be
subject to browser clipboard permissions, so the comparison must measure the
actual developer path rather than only whether a desktop appears.

KasmVNC is the first candidate. It packages a modern browser-native client,
offers an explicit clipboard panel and keyboard-shortcut controls, and ships
Debian-compatible release packages. Xpra remains the control candidate because
its HTML5 client can forward individual windows and supports adaptive encoding,
but its own documentation notes that browser clipboard access still needs a
gesture or browser permission.

## Prototype contract

Each candidate image must:

- remain unprivileged and listen only on the Sandbox loopback interface;
- use a distinct declared port (`6901` for KasmVNC, `14500` for Xpra);
- generate any server identity at lease start, never at image build;
- start Firefox, a terminal, and a Kunobi/Tauri process on the same desktop;
- preserve noVNC as the fallback in the production GUI image; and
- build for every Kobe-supported image architecture before it is considered a
  production replacement.

## Acceptance run

For each candidate and noVNC, use one fresh 32 GiB GUI lease and record:

1. Time from `kobe-desktop start` to a usable desktop.
2. Browser page paint and DevTools text readability at 100% and 125% zoom.
3. Copy/paste in both directions for plain text, Unicode, and a multiline
   GitHub token-shaped value without logging the value.
4. Terminal shortcuts: Ctrl+C, Ctrl+V, Ctrl+Shift+V, Alt, Super, and an
   international-layout character.
5. Firefox OAuth completed inside the remote desktop.
6. A Kunobi development rebuild and visible hot reload.
7. CPU, resident memory, and bytes sent while idle and during a rebuild.
8. Reconnect after closing and reopening the local port forward.

The replacement must pass every functional scenario and improve either text
clarity or clipboard reliability without a material startup or resource cost.
Otherwise noVNC remains the default and the experiment is documented with its
measurements.
