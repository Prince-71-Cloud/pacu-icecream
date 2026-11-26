# Pacu Web GUI

A local, browser-based front-end for the [Pacu](https://github.com/RhinoSecurityLabs/pacu)
AWS exploitation framework.

It runs **one real Pacu engine** (`pacu.Main`) in a background thread and drives it
through the framework's own command dispatcher — nothing is re-implemented. The browser
is just a nicer way to set keys, pick modules, and watch output.

## What it gives you

- **Sessions** — create / switch Pacu sessions.
- **AWS keys** — set key alias, access key ID, secret, and (optional) session token.
- **Default Regions** — pick the session's default regions (Pacu `set_regions`) from a dropdown,
  shown as removable chips. Setting one or more specific regions stops modules from prompting
  "run against all regions?" on every run; the **All** button resets to all-regions (prompting).
- **Module browser** — all Pacu modules, searchable, grouped by category, each rendered
  as a form built from the module's real argparse arguments (checkboxes for switches,
  text/select fields for values). A live `Pacu> run ...` command preview updates as you type.
- **Session Data panel** — a tab showing the AWS data Pacu has enumerated into the active
  session (`get_all_aws_data_fields_as_dict`), grouped by service as collapsible JSON.
- **Loot / Files panel** — a tab listing every file written under the session directory
  (`~/.local/share/pacu/<session>/`: downloads, module data, logs), newest first, with an
  inline viewer for text files and a **Download** button to save any file (text or binary)
  to your machine. Path access is confined to the session directory.
- Both panels auto-refresh when a module finishes, and have a manual **Refresh** button.
- **Live terminal** — streams the engine's output over Server-Sent Events.
- **Interactive prompts** — when a module asks a question, an input box appears inline and
  your answer is fed straight back to the running module.
- **Quick actions + raw command** — one-click `whoami`, `regions`, honeytoken check, etc.,
  plus a box for any command you'd type at the `Pacu>` prompt.

## Run

```bash
pacu-web                                 # http://127.0.0.1:8088
# or
python -m pacu.web
# custom port / host:
python -m pacu.web --port 9000 --host 127.0.0.1
```

Then open <http://127.0.0.1:8088> in your browser.

Requires Flask. Install it with the `web` extra (`pip install -e ".[web]"` or `poetry install -E web`), or `pip install flask`. `pacu-web` needs an install to register; `python -m pacu.web` works from a checkout without one. The `pacu` package must be importable

## Important

- Binds to **127.0.0.1** by default. This UI gives full, unauthenticated control of a
  security tool that makes real AWS API calls with whatever keys you set. **Do not** expose
  it on an untrusted network. Binding to a non-loopback host prints a warning.
- It reuses Pacu's normal SQLite database (`~/.local/share/pacu/sqlite.db`), so sessions and
  keys are shared with the `pacu` CLI.
- Only use it against AWS accounts you are authorized to test.

## How it maps to the engine

| GUI action            | Engine call                                   |
|-----------------------|-----------------------------------------------|
| Run module / command  | `Main.parse_command("run <module> <args>")`   |
| Set keys              | `Main.set_keys(alias, id, secret, token)`     |
| New / switch session  | `Main.new_session` / `Main.activate_session`  |
| Set default regions   | `Main.parse_set_regions_command(...)`          |
| Module metadata       | each module's `module_info` + argparse parser |
| Output                | `Main.print` / stdout → SSE                    |
| Prompts               | `Main.input` / builtin `input` → POST /api/input |
| Session Data panel    | `PacuSession.get_all_aws_data_fields_as_dict()` |
| Loot / Files panel    | files under `pacu.core.lib.session_dir()`      |
