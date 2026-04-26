# VS Code extension scaffold (optional)

This folder is a **minimal stub** to wrap `vendor/bin/laravel-shield` or a global `laravel-shield` binary from the editor.

## Usage

1. Open this folder in VS Code.
2. Run `npm install` (add a `package.json` with `@types/vscode` and `vsce` if you want to package).
3. In `extension.js` or `out/extension.js`, use `child_process.spawn` to run:

   - `php` / `vendor/bin/laravel-shield` in the current workspace root.
4. Expose a command, e.g. `laravel-shield.run`, bound in `contributes`.

This is not a full published extension; it is a starting point to hook the CLI you already have.
