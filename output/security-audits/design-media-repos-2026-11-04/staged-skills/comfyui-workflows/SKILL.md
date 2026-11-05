---
name: comfyui-workflows
description: Design, inspect, troubleshoot, and integrate ComfyUI image or video workflow graphs and API-format JSON. Use for ComfyUI node connections, model compatibility, local queue execution, and output retrieval. This is workflow guidance; it does not install ComfyUI, models, custom nodes, or a GPU runtime.
metadata:
  source-repository: https://github.com/Comfy-Org/ComfyUI
  reviewed-commit: 56f179f6c50dad0c4c860ae4da427415c8e86415
  reviewed-date: "2026-11-04"
---

# ComfyUI workflows

Work with the user's existing ComfyUI instance or workflow files. Establish whether the deliverable is an editable UI workflow, API prompt JSON, a client integration, or generated media. Preserve existing node IDs, useful metadata, and the user's chosen model family where possible.

## Inspect before changing a graph

- Distinguish the UI graph export (`nodes`, `links`, widget/layout metadata) from API-format JSON (node-ID keys with `class_type` and `inputs`). They are not interchangeable. Request an API export when a UI graph cannot be converted reliably from the available node definitions.
- Use the selected instance's `/object_info` or `/object_info/{node_class}` to verify node names, required inputs, enumerations, and output slots. If no instance is available, inspect local definitions or supplied metadata and label the graph as unexecuted. Do not invent node types or claim a model is installed.
- Check that referenced node IDs exist, output-slot indices and types fit the receiving inputs, and model/CLIP/VAE/latent families are compatible. Trace missing-model errors to actual configured paths rather than substituting filenames.
- Inspect custom nodes before suggesting installation. They are executable Python, including startup hooks. Workflow JSON is not a sandbox for them. Prefer available built-in nodes for the requested result.

## Build and diagnose

For a simple image pipeline, trace model and conditioning through latent creation, sampling, decoding, and a save/preview output. For video or specialized architectures, use the actual model's required node interfaces instead of adapting a Stable Diffusion graph by guesswork. Keep seeds and generation parameters explicit when reproducibility matters; a fixed seed alone does not guarantee identical results across hardware or versions.

Make the smallest graph change that addresses the observed error. Distinguish schema/connection validation, model availability, GPU/VRAM failures, and output quality. Reduce dimensions or batch size only when appropriate to the user's quality requirements, and report that change.

## Queue execution and retrieve evidence

Read [API integration](references/api-integration.md) when connecting a client or executing a graph. A request to create or inspect a workflow alone does not authorize submitting it. When execution is already part of the user's request, continue within that authorization; do not ask again just because a queue submission is needed.

Use prompt-scoped status and history, bounded waits, and actual output metadata. A queue response is acceptance, not a finished render. Report validation errors and execution failures accurately. Inspect the resulting image/video before claiming the visual brief was met.

## Trust boundaries

- Keep a local instance bound to loopback. Remote exposure requires a separately secured deployment; ComfyUI's multi-user profile header is not a substitute for authentication or tenant isolation.
- Do not install or start ComfyUI, a manager, custom nodes, package dependencies, or model downloads just because this skill was loaded. Perform those operations only when the current request authorizes them and the selected artifacts have been reviewed. This skill installation does not approve the runtime dependency graph.
- Review model provenance and prefer appropriate safetensors artifacts. Never weaken the application's `weights_only` model-loading protection to make an untrusted checkpoint load.
- Cloud/partner nodes can upload inputs and incur charges. Respect existing authorization for that destination and operation; otherwise prepare the graph and identify the upload/cost decision before executing it. Do not transmit private project data to a provider by default.
- Keep API keys on the server or in the user's configured secret store. Never put credentials in workflow exports, screenshots, saved reports, or chat.

Reviewed upstream source: [ComfyUI at the pinned commit](https://github.com/Comfy-Org/ComfyUI/tree/56f179f6c50dad0c4c860ae4da427415c8e86415). Consult the instance version and current official documentation when APIs differ. This skill includes no upstream application code or model weights.
