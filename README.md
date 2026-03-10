# md-portal

A clean, mobile first portal to share markdown documents as polished web pages.

## Why this project

Most markdown notes are hard to read on phones and messy to share.
md-portal turns them into a simple reading experience with private link support and lightweight access control.

## Highlights

- Clean monochrome reading UI
- One click share for private note links
- Root portal password gate with blur lock screen
- Private note links that open directly
- Download button for original markdown file
- Fast publish flow for daily reports and docs

## Use cases

- Share project reports with external partners
- Send long technical docs in phone friendly format
- Keep an internal notes portal and still expose only selected docs

## Quick start

1. Install dependencies
2. Configure `.env` from `.env.example`
3. Run `./run.sh`
4. Publish a note with `./publish.sh <path-to-markdown>`

## Link behavior

- `https://<domain>/` -> protected portal view
- `https://<domain>/private/?note=...&token=...` -> direct private document view

## License

MIT
