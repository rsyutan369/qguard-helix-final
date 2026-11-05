# API integration

Use the user-selected ComfyUI instance. The upstream local default is `http://127.0.0.1:8188`; do not assume an instance is running or send credentials to an inferred address. Use HTTPS/WSS and the deployment's authentication for a remote instance.

## Workflow format and execution

The API graph is an object keyed by node ID. Each node has a `class_type` and an `inputs` object; connected inputs use `["source_node_id", output_slot_index]`. A UI workflow export also carries layout/widget information and is not the same payload.

Read the node schema from the actual instance. A structural JSON check does not establish that model files exist or that execution will succeed. Submit through `POST /prompt` only when executing is within the current request. The body carries `prompt` and can carry a unique `client_id`; retain the returned `prompt_id` and any `node_errors`.

Avoid automatic retries of uncertain queue submissions: a lost response can mean the job was already accepted. Reconcile the current queue/history before resubmitting. Bound connection and execution waits, and retain only the metadata necessary to identify the user's job.

## Track a job

Connect to `/ws?clientId=<client_id>` before submitting when real-time updates are needed. Scope events by `prompt_id`; do not report another job's progress. Handle execution-error and interruption events. The upstream example treats `executing` with `node: null` for the matching prompt as completion, then retrieves `/history/{prompt_id}`. Confirm outputs and error status in history before reporting success; not every workflow produces image files.

If the WebSocket disconnects, reconnect with bounded retries and reconcile prompt-scoped history/queue state. Do not manufacture percent complete from elapsed time. Poll history with a reasonable interval when streaming is unavailable, and state the limitation.

## Retrieve artifacts safely

Use filenames, subfolders, and folder types from the completed job's output metadata for `/view`, encoded as query parameters. Save to an explicit project output directory. Treat server-supplied names as untrusted: reject absolute paths and traversal, sanitize or generate local basenames, and check resolved paths stay under the output directory. Do not execute downloaded files or follow output metadata to unrelated hosts.

`POST /interrupt` can affect the current shared execution, while queue/history mutation endpoints may affect other jobs. Do not use global cleanup/cancellation to manage one request on a shared instance. Inspect the current job ownership and available prompt-specific cancellation support before any such mutation.

## Sources

- [Pinned upstream HTTP/WebSocket example](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/script_examples/websockets_api_example.py)
- [Pinned upstream server routes](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/server.py)
- [Official API route documentation](https://docs.comfy.org/development/comfyui-server/comms_routes)
- [Pinned upstream security policy](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/SECURITY.md)
