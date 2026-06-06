# Windows Launcher Guide

This guide explains how to run the local receiver and dashboard together on
Windows with the launcher scripts.

The launcher is a local convenience wrapper. It does not change the security
boundary of the gateway:

- receiver binds to `127.0.0.1`
- dashboard binds to `127.0.0.1`
- launcher output is raw-free metadata only
- PID and launcher logs are written under ignored `out\.launcher\` files
- raw request or response values are never printed by the launcher

Do not paste real Burp data, customer domains, tokens, cookies, session values,
personal data, HMAC secrets, or CSRF values into chat, issues, PRs, reports, or
documentation.

## Start From PowerShell

From the repository root:

```powershell
scripts\start_gateway.ps1
```

Default startup values:

| Setting | Default |
| --- | --- |
| Receiver host | `127.0.0.1` |
| Receiver port | `8765` |
| Dashboard host | `127.0.0.1` |
| Dashboard port | `8766` |
| Output alias | `out\receiver` |
| Project alias | `receiver_alias` |
| Dashboard URL | `http://127.0.0.1:8766/` |
| Launcher state | `out\.launcher\` |

The launcher starts the receiver, starts the dashboard, opens the dashboard URL
in a browser, and prints only safe metadata such as ports, output alias, project
alias, process ids, and `raw_data_included=false`.

To start without opening a browser:

```powershell
scripts\start_gateway.ps1 -NoBrowser
```

## Start From CMD

CMD users can run the wrapper:

```bat
scripts\start_gateway.bat
```

The BAT wrapper calls the PowerShell launcher with the same arguments.

## Stop The Launcher

Stop the receiver and dashboard that were started by the launcher:

```powershell
scripts\stop_gateway.ps1
```

The stop script reads the launcher PID files and checks that each PID still
belongs to this gateway command before calling `Stop-Process`.

It refuses to stop an unexpected process. This protects against stale or edited
PID files pointing at unrelated local processes.

## PowerShell Execution Policy

Some Windows environments block `.ps1` script execution. If that happens, keep
the workaround scoped to the current PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
scripts\start_gateway.ps1
```

`-Scope Process` applies only to the current PowerShell process. It does not
change the machine-wide or user-wide policy.

You can also use the CMD wrapper:

```bat
scripts\start_gateway.bat
```

## Port Conflict Troubleshooting

The receiver and dashboard must use different free loopback ports.

Common safe startup failures:

| Error type | Meaning | Next step |
| --- | --- | --- |
| `receiver_port_in_use` | Port `8765` is already in use. | Stop the existing local service or start with another receiver port. |
| `dashboard_port_in_use` | Port `8766` is already in use. | Stop the existing local service or start with another dashboard port. |
| `ports_must_be_distinct` | Receiver and dashboard ports are the same. | Use two different ports. |

Example with alternate ports:

```powershell
scripts\start_gateway.ps1 -ReceiverPort 8875 -DashboardPort 8876
```

Then open:

```text
http://127.0.0.1:8876/
```

## Output Alias Troubleshooting

The launcher accepts a safe output alias under `out\` only.

Allowed example:

```powershell
scripts\start_gateway.ps1 -Output out\receiver -Project receiver_alias
```

Blocked examples:

| Input | Safe error type |
| --- | --- |
| `..\raw` | `output_must_be_under_out` |
| `C:\temp\receiver` | `absolute_output_path_not_allowed` |
| `out\..\receiver` | `path_traversal_not_allowed` |
| `out\raw` | `forbidden_output_directory` |

The project value is an alias. Do not use a real customer name.

## PID File Troubleshooting

Launcher PID files are local state under:

```text
out\.launcher\
```

The files are ignored by Git and must not be committed.

If a PID file points to a process that is not a gateway receiver or dashboard,
the stop script prints:

```text
unexpected_process
```

In that case, the stop script intentionally leaves the process running. Remove
only the stale launcher PID file after confirming it is not related to the
gateway.

## Safe Output Boundary

Launcher console output and launcher logs may include:

- receiver port
- dashboard port
- output alias
- project alias
- process id
- safe error type
- `raw_data_included=false`

Launcher console output and launcher logs must not include:

- raw request or response data
- Cookie values
- Authorization values
- token, JWT, or session values
- real target URLs, domains, or internal IPs
- customer names or personal data
- HMAC secrets
- CSRF values
- full stack traces

## Quick Check

After startup:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8765/health
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8766/
```

Expected result:

- receiver health returns HTTP `200`
- dashboard returns HTTP `200`
- dashboard URL is `http://127.0.0.1:8766/`

Stop after checking:

```powershell
scripts\stop_gateway.ps1
```
