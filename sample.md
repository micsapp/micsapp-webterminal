# Markdown preview sample

Open this file in the web terminal file browser. The diagram should appear as a rendered flowchart, followed by two copies of the blue SVG card. Switch between **Source** and **Rendered** in the preview toolbar to compare.

## Mermaid flowchart

```mermaid
flowchart LR
    A[Open sample.md] --> B{Preview mode?}
    B -->|Rendered| C[Draw flowchart]
    B -->|Source| D[Show Markdown text]
    C --> E[Display SVG images]
```

## SVG with Markdown image syntax

![Blue SVG card rendered through the file API](sample.svg)

## SVG with an HTML image tag

<img src="sample.svg" alt="The same blue SVG card rendered from an HTML image tag">

The two images should remain visible even if you browse to another folder while this preview stays open.
