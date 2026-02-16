# Inspector Findings — Project Memory

## Overview

Shiny for Python application for fetching and analyzing AWS Inspector findings. Single-file app (`app.py`) using `bslib` (via `ui.Theme("flatly")`) for the UI framework and `boto3` for AWS API calls.

## File Structure

- `app.py` — The complete Shiny for Python application (single-file, ~1070 lines)
- `www/` — Static files directory (automatically served at root path)
  - `favicon.ico` — Simple "I" favicon (32x32 and 16x16, generated with PIL)
- `example-findings.json` — Sample findings file for demos (enables conditional "Load Example Data" button)
- `requirements.txt` — Python dependencies (install with `uv pip install -r requirements.txt`)
- `.venv/` — uv-managed virtual environment (Python 3.13)
- `inspector-findings.Rproj` — RStudio project file
- `AGENTS.md` — This project memory file

## Running

```bash
# Activate venv and run
.venv/Scripts/activate   # Windows
shiny run app.py
```

## Dependencies

Listed in `requirements.txt`. Install with `uv pip install -r requirements.txt`.

- `shiny[theme]>=1.5.0` — Shiny for Python web framework (includes `libsass` for Bootswatch theme compilation)
- `boto3` — AWS SDK for Python; used to call `inspector2.list_findings()` directly
- `pandas` — DataFrame manipulation for findings data
- `matplotlib` — Plotting (severity charts, timeline, pie charts)

## Architecture

### Static Files

The app serves static files (favicon, etc.) from the `www/` directory via the `static_assets` parameter on the `App` object. Files in `www/` are accessible at the root path (e.g., `www/favicon.ico` → `/favicon.ico`).

### Data Flow

Three paths to load findings into the app:

**Path A — Fetch via API (default):**
1. User clicks "Fetch Findings" in the sidebar
2. `boto3.Session().client("inspector2")` is created from region/profile/credential inputs
3. Paginated `list_findings()` calls run in an `async` server function with `await asyncio.sleep(0)` between pages (yields to Shiny event loop for streaming log updates)
4. Raw findings are flattened to a DataFrame by `flatten_finding()` and stored in `findings_rv` reactive value

**Path B — Generate CLI Command + Upload:**
1. User selects "Generate AWS CLI Command" fetch mode
2. Clicks "Generate CLI Command" button → modal shows a self-contained Python script that:
   - Uses `subprocess.run()` to invoke the `aws` CLI with pagination via `--next-token`
   - Parses responses with `json.loads(strict=False)` to handle bare control characters
   - Collects all pages and writes valid JSON via `json.dump()` to `findings.json`
3. User saves as `.py`, runs with `python3 fetch_findings.py`
4. User uploads the resulting JSON via the "Upload Findings JSON" file input
5. `parse_cli_json()` parses the JSON (handles single response, array of pages, or flat finding array) into the same DataFrame schema

**Path C — Load Example Data:**
1. "Load Example Data" button appears conditionally when `example-findings.json` exists
2. Reads and parses the file through the same `parse_cli_json()` pipeline

All paths end at `findings_rv` (`reactive.value`). All downstream outputs (value boxes, data frame, plots, modal) react to `findings_rv`.

### Key Design Decisions

- **Async pagination** — The fetch handler is an `async def` that uses `await asyncio.sleep(0)` between pages to yield to the Shiny event loop, allowing log updates to stream to the UI.
- **Cancellation** — A `cancel_flag` reactive value is checked before each page.
- **Button visibility via `send_custom_message`** — No shinyjs dependency. Uses `session.send_custom_message("eval_js", js_code)` with a custom JS handler registered in `tags.head()`.
- **`findings_rv` is the single source of truth** — The DataTable handles its own filtering/sorting; plots and value boxes read from `findings_rv` directly.
- **Control character handling** — AWS CLI may emit bare newlines/tabs in finding descriptions (invalid JSON). Handled at three layers:
  1. Generated Python script uses `json.loads(strict=False)` + `json.dump()` to re-serialize cleanly
  2. Upload path applies `sanitize_json_strings()` as fallback
  3. `parse_cli_json()` always calls `sanitize_json_strings()` before `json.loads()`
- **Clipboard cross-platform** — `copyToClipboard()` JS helper tries `navigator.clipboard.writeText()` first, falls back to `document.execCommand('copy')` via temporary textarea.

### Sidebar Controls

**AWS Connection** (collapsible accordion, collapsed by default):
- Region (defaults from `AWS_DEFAULT_REGION` env var, fallback `us-east-1`)
- Named profile (from `AWS_PROFILE` env var)
- Explicit access key / secret key / session token
- Priority: explicit keys > named profile > default credential chain

**Filters** (applied at API level, before fetch):
- Severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL, UNTRIAGED (defaults: CRITICAL, HIGH, MEDIUM)
- Status: ACTIVE, SUPPRESSED, CLOSED (default: ACTIVE)
- Resource Type: Container Image, ECR Repository, EC2 Instance, Lambda Function, Account (empty = all)
- Container images in use (ECS/EKS only): checkbox that adds `ecrImageInUseCount >= 1` filter

**Actions:**
- Fetch Mode radio (API vs. Generate CLI Command)
- Fetch/Generate CLI/Cancel buttons with dynamic visibility
- Export CSV download button
- Upload Findings JSON file input
- Load Example Data button (conditional on `example-findings.json` existing)
- Short status text

### Findings Data Schema (22 columns)

Core fields: `findingArn`, `severity`, `status`, `type`, `title`, `description`, `firstObservedAt`, `lastObservedAt`, `updatedAt`, `inspectorScore`, `resourceType`, `resourceId`, `resourceRegion`, `accountId`, `fixAvailable`, `exploitAvailable`

ECR container image fields (None for non-container findings): `imageRepo`, `imageTags`, `imageDigest`, `imageRegistry`, `imageArch`, `imagePushedAt`

Date columns are parsed to `pd.Timestamp` (UTC) after fetch.

### UI Components

- **Page title** — "AWS Inspector Findings" with GitHub link icon (https://github.com/statik/inspector-findings)
- **Value boxes** — Total, Critical, High, Fix Available counts
- **DataTable** (`render.data_frame` with `render.DataTable`) — Sortable, filterable, single row selection, 600px height
- **Row-click detail modal** — Full finding details in a CSS grid layout. Includes:
  - Color-coded severity badge in title
  - Copy ARN button (clipboard)
  - Copy as JSON button (footer, serializes full row via `json.dumps`)
  - Resource ID links to AWS Console (`aws_console_url()` helper)
  - Conditional container image section
  - Description in pre-wrap format
- **Analysis tabs** (via `navset_card_tab`):
  - Severity Breakdown: severity bar chart + resource type horizontal bar chart
  - Timeline: daily new findings (vertical lines by `firstObservedAt`)
  - Exploit & Fix Status: two pie charts
  - All charts use `matplotlib`
- **Fetch Log** — Dark terminal-style pane at bottom, streams timestamped log lines, auto-scrolls via injected JS, has Clear button

### Helper Functions

- `log_line(*parts)` — Timestamped log string
- `flatten_finding(f)` — Single API finding dict → flat row dict (including ECR image fields)
- `findings_to_df(findings)` — List of finding dicts → pandas DataFrame
- `build_filter(severities, statuses, resource_types, ecr_in_use)` — Constructs Inspector2 `filterCriteria` dict
- `aws_console_url(resource_type, resource_id, region)` — Maps resource to AWS Console URL (EC2, ECR, Lambda, Account, with fallback)
- `build_cli_command(region, profile, severities, statuses, resource_types, ecr_in_use)` — Returns list of CLI args for `aws inspector2 list-findings`
- `build_python_script(cli_parts)` — Generates a self-contained Python pagination script from CLI args
- `parse_cli_json(json_text)` — Parses JSON output from the AWS CLI; applies `sanitize_json_strings()` first; returns `(df, error)` tuple; accepts single `{findings: [...]}`, array of pages, or flat array
- `sanitize_json_strings(json_text)` — Regex-based string token fixer that escapes bare control chars inside JSON string literals

### Constants

- `SEVERITY_COLORS` — Dict mapping severity levels to hex colors
- `SEVERITY_LEVELS` — Ordered list of severity level names
- `RESOURCE_TYPE_CHOICES` — Display name → API value mapping for resource type filter
- `FINDING_COLUMNS` — Ordered list of all 22 column names
- `TABLE_COLUMNS` — Subset of columns shown in the DataTable view
