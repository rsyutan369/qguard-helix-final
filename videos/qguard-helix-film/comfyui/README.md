# ComfyUI environment plates

These five ComfyUI API prompts produce clean environment stills for the QGUARD HELIX film. The shot descriptions reserve space for the typography, supplied logo, and actual app captures that Remotion composites separately. The pinned ComfyUI source was used for offline validation. No local generation run was verified.

| API prompt | Shot |
| --- | --- |
| `earth.api.json` | Low orbit at night, with city lights below a clear blue horizon |
| `lab.api.json` | A grounded quantum research lab around a suspended cryogenic instrument |
| `archive.api.json` | An archival-drive close-up for the Harvest Now, Decrypt Later sequence |
| `rural.api.json` | A quiet, remote forest valley for the Offgrid Mesh sequence |
| `energy-core.api.json` | Cyan and violet optical effects behind the closing logo reveal |

Each graph uses the SDXL base Safetensors checkpoint, built-in ComfyUI nodes, and an explicit seed. The model filename in node 1 must match the exact entry in the intended instance's checkpoint list. The starting landscape plate is 1344 × 768. For a separate portrait take, change node 4 to 768 × 1344 and refine the framing in node 2 for the 9:16 edit. Composite a slight crop and camera push in Remotion when using these stills in motion.

## Run one plate locally

From this directory, select the loopback address of an already running ComfyUI instance. The example checks the installed checkpoint list. Submit the graph after confirming that checkpoint and the node definitions are available in `/object_info`.

```powershell
$comfyApi = 'http://127.0.0.1:8188'
$plate = Get-Content -Raw -LiteralPath ./earth.api.json | ConvertFrom-Json -AsHashtable
$loader = Invoke-RestMethod "$comfyApi/object_info/CheckpointLoaderSimple"
$checkpoints = $loader.CheckpointLoaderSimple.input.required.ckpt_name[0]
if ($checkpoints -notcontains $plate['1'].inputs.ckpt_name) {
    throw 'This graph requires an installed SDXL base checkpoint. Check the loader list.'
}

$request = @{ prompt = $plate; client_id = [guid]::NewGuid().ToString() }
$job = Invoke-RestMethod -Uri "$comfyApi/prompt" -Method Post -ContentType 'application/json' -Body ($request | ConvertTo-Json -Depth 20)
$job.prompt_id
```

Inspect `GET /history/{prompt_id}` until the entry reports success or an error. A new prompt ID means the queue accepted the job. On success, node 7's output metadata identifies the image under the instance's `output/qguard-helix-plates/` directory. Inspect the image for artifacts, readable pseudo-text, and crop quality before using it.

Sources for the graph definitions and checkpoint are the [pinned ComfyUI core nodes](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/nodes.py), [pinned samplers](https://github.com/Comfy-Org/ComfyUI/blob/56f179f6c50dad0c4c860ae4da427415c8e86415/comfy/samplers.py), [ComfyUI API routes](https://docs.comfy.org/development/comfyui-server/comms_routes), and [Stability AI's SDXL base model and license](https://huggingface.co/stabilityai/stable-diffusion-xl-base-1.0).

## Existing project motion plates

The film project also includes two reusable assets already tracked in Qguard Helix. Visual review sampled each asset throughout its duration.

| Film asset | Workspace source | Format |
| --- | --- | --- |
| `public/plates/lab.mp4` | Repository root `public/helix-features/hero-quantum-migration.mp4` | 1920 × 1080 at 24 FPS, 10.04 s. Cyan server corridor with a brighter energy pulse around the second half. |
| `public/plates/vault.mp4` | Repository root `public/migration-hero/strata/glass-layers.mp4` | 960 × 960 at 24 FPS, 5.04 s. Violet and cyan stacked glass illustration. |
