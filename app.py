"""
AWS Inspector Findings — Shiny for Python application.

Fetches, displays, and analyzes AWS Inspector findings using boto3 and bslib.
Run with: shiny run app.py
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3
import pandas as pd
from htmltools import HTML, Tag, TagList, css, tags
from shiny import App, Inputs, Outputs, Session, reactive, render, ui

# -- Constants ----------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#0dcaf0",
    "INFORMATIONAL": "#6c757d",
    "UNTRIAGED": "#adb5bd",
}

SEVERITY_LEVELS = list(SEVERITY_COLORS.keys())

RESOURCE_TYPE_CHOICES = {
    "Container Image": "AWS_ECR_CONTAINER_IMAGE",
    "ECR Repository": "AWS_ECR_REPOSITORY",
    "EC2 Instance": "AWS_EC2_INSTANCE",
    "Lambda Function": "AWS_LAMBDA_FUNCTION",
    "Account": "AWS_ACCOUNT",
}

FINDING_COLUMNS = [
    "findingArn", "severity", "status", "type", "title", "description",
    "firstObservedAt", "lastObservedAt", "updatedAt", "inspectorScore",
    "resourceType", "resourceId", "resourceRegion", "accountId",
    "fixAvailable", "exploitAvailable",
    "imageRepo", "imageTags", "imageDigest", "imageRegistry", "imageArch",
    "imagePushedAt",
]

TABLE_COLUMNS = [
    "severity", "status", "title", "resourceType", "resourceId",
    "inspectorScore", "fixAvailable", "exploitAvailable", "lastObservedAt",
]

EXAMPLE_FILE = Path(__file__).parent / "example-findings.json"

# -- Helpers ------------------------------------------------------------------


def log_line(*parts: str) -> str:
    """Return a timestamped log string."""
    ts = datetime.now().strftime("%H:%M:%S")
    return f"[{ts}] {''.join(str(p) for p in parts)}"


def _get(d: dict, *keys: str, default=None):
    """Safely traverse nested dicts."""
    current = d
    for k in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(k, default)
    return current


def flatten_finding(f: dict) -> dict:
    """Flatten a single API finding dict into a flat row dict."""
    resource = (f.get("resources") or [{}])[0] if f.get("resources") else {}
    ecr = _get(resource, "details", "awsEcrContainerImage", default={}) or {}

    image_tags_raw = ecr.get("imageTags")
    image_tags = ", ".join(image_tags_raw) if image_tags_raw else None

    return {
        "findingArn": f.get("findingArn"),
        "severity": f.get("severity"),
        "status": f.get("status"),
        "type": f.get("type"),
        "title": f.get("title"),
        "description": f.get("description"),
        "firstObservedAt": str(f["firstObservedAt"]) if f.get("firstObservedAt") else None,
        "lastObservedAt": str(f["lastObservedAt"]) if f.get("lastObservedAt") else None,
        "updatedAt": str(f["updatedAt"]) if f.get("updatedAt") else None,
        "inspectorScore": float(f["inspectorScore"]) if f.get("inspectorScore") is not None else None,
        "resourceType": resource.get("type"),
        "resourceId": resource.get("id"),
        "resourceRegion": resource.get("region"),
        "accountId": f.get("awsAccountId"),
        "fixAvailable": f.get("fixAvailable"),
        "exploitAvailable": f.get("exploitAvailable"),
        "imageRepo": ecr.get("repository"),
        "imageTags": image_tags,
        "imageDigest": ecr.get("imageHash"),
        "imageRegistry": ecr.get("registryId"),
        "imageArch": ecr.get("architecture"),
        "imagePushedAt": str(ecr["pushedAt"]) if ecr.get("pushedAt") else None,
    }


def findings_to_df(findings: list[dict]) -> pd.DataFrame:
    """Convert a list of raw finding dicts to a DataFrame."""
    if not findings:
        return pd.DataFrame(columns=FINDING_COLUMNS)
    rows = [flatten_finding(f) for f in findings]
    df = pd.DataFrame(rows, columns=FINDING_COLUMNS)
    for col in ("firstObservedAt", "lastObservedAt", "updatedAt"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")
    return df


def build_filter(
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    resource_types: list[str] | None = None,
    ecr_in_use: bool = False,
) -> dict:
    """Build Inspector2 filterCriteria dict."""
    criteria: dict = {}
    if severities:
        criteria["severity"] = [
            {"comparison": "EQUALS", "value": s} for s in severities
        ]
    if statuses:
        criteria["findingStatus"] = [
            {"comparison": "EQUALS", "value": s} for s in statuses
        ]
    if resource_types:
        criteria["resourceType"] = [
            {"comparison": "EQUALS", "value": r} for r in resource_types
        ]
    if ecr_in_use:
        criteria["ecrImageInUseCount"] = [{"lowerInclusive": 1}]
    return criteria


def aws_console_url(
    resource_type: str | None,
    resource_id: str | None,
    region: str | None,
) -> str | None:
    """Map a resource to an AWS Console URL."""
    if not resource_type or not resource_id or not region:
        return None
    base = f"https://{region}.console.aws.amazon.com"
    urls = {
        "AWS_EC2_INSTANCE": f"{base}/ec2/home?region={region}#InstanceDetails:instanceId={resource_id}",
        "AWS_ECR_CONTAINER_IMAGE": f"{base}/ecr/repositories?region={region}",
        "AWS_ECR_REPOSITORY": f"{base}/ecr/repositories/private/{resource_id}?region={region}",
        "AWS_LAMBDA_FUNCTION": f"{base}/lambda/home?region={region}#/functions/{resource_id}",
        "AWS_ACCOUNT": f"{base}/inspector/v2/home?region={region}",
    }
    return urls.get(resource_type, f"{base}/inspector/v2/home?region={region}#/findings")


def sanitize_json_strings(json_text: str) -> str:
    """Escape bare control chars inside JSON string tokens."""
    replacements = {
        "\t": "\\t",
        "\n": "\\n",
        "\r": "\\r",
        "\b": "\\b",
        "\f": "\\f",
    }

    def fix_string(m: re.Match) -> str:
        s = m.group(0)
        inner = s[1:-1]
        # Protect already-escaped sequences
        inner = inner.replace("\\\\", "\x01")
        for char, escaped in replacements.items():
            inner = inner.replace(char, escaped)
        inner = inner.replace("\x01", "\\\\")
        return f'"{inner}"'

    return re.compile(r'(?s)"(?:[^"\\]|\\.)*"').sub(fix_string, json_text)


def parse_cli_json(json_text: str) -> tuple[pd.DataFrame | None, str | None]:
    """Parse CLI JSON output into a DataFrame.

    Returns (df, error). On success error is None; on failure df is None.
    """
    json_text = sanitize_json_strings(json_text)
    try:
        parsed = json.loads(json_text)
    except json.JSONDecodeError as e:
        return None, str(e)

    findings_list: list | None = None
    if isinstance(parsed, dict) and "findings" in parsed:
        findings_list = parsed["findings"]
    elif isinstance(parsed, list) and parsed:
        if isinstance(parsed[0], dict) and "findings" in parsed[0]:
            findings_list = []
            for page in parsed:
                findings_list.extend(page.get("findings", []))
        elif isinstance(parsed[0], dict) and "findingArn" in parsed[0]:
            findings_list = parsed

    if findings_list is None:
        return None, (
            "Unrecognized JSON structure. Expected an object with a 'findings' key, "
            "an array of such objects, or a flat array of finding objects."
        )

    return findings_to_df(findings_list), None


def build_cli_command(
    region: str,
    profile: str,
    severities: list[str],
    statuses: list[str],
    resource_types: list[str],
    ecr_in_use: bool = False,
) -> str:
    """Build an aws inspector2 list-findings CLI command string."""
    parts = ["aws", "inspector2", "list-findings"]
    if region:
        parts.extend(["--region", region])
    if profile:
        parts.extend(["--profile", profile])

    criteria = build_filter(severities, statuses, resource_types, ecr_in_use)
    if criteria:
        criteria_json = json.dumps(criteria, separators=(",", ":"))
        parts.extend(["--filter-criteria", criteria_json])

    parts.extend(["--max-results", "100", "--no-paginate", "--output", "json"])
    return parts


def build_python_script(cli_parts: list[str]) -> str:
    """Build a self-contained Python pagination script from CLI args."""
    # Remove 'aws' prefix — we invoke via subprocess
    args_without_aws = cli_parts[1:]
    args_str = repr(args_without_aws)

    return f"""\
import subprocess, json, sys

args = {args_str}
token = None
all_findings = []
page = 0

while True:
    page += 1
    call = ['aws'] + args
    if token:
        call += ['--next-token', token]
    print(f'Fetching page {{page}}...', file=sys.stderr)
    result = subprocess.run(call, capture_output=True, text=True)
    if result.returncode != 0:
        print(f'Error: {{result.stderr}}', file=sys.stderr)
        sys.exit(1)
    data = json.loads(result.stdout, strict=False)
    findings = data.get('findings', [])
    all_findings.extend(findings)
    print(f'  Page {{page}}: {{len(findings)}} findings (total: {{len(all_findings)}})', file=sys.stderr)
    token = data.get('nextToken')
    if not token:
        break

with open('findings.json', 'w') as f:
    json.dump({{'findings': all_findings}}, f)

print(f'Done. Wrote {{len(all_findings)}} findings to findings.json', file=sys.stderr)
"""


# -- Custom JS ----------------------------------------------------------------

CUSTOM_JS = tags.head(
    tags.link(
        rel="stylesheet",
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css",
    ),
    tags.script(
        HTML("""\
/* eval_js message handler — runs arbitrary JS sent from the server */
Shiny.addCustomMessageHandler('eval_js', function(msg) { eval(msg); });

/* Clipboard helper with execCommand fallback for non-secure contexts */
function copyToClipboard(text, btn) {
    function onSuccess() {
        if (!btn) return;
        var orig = btn.innerHTML;
        btn.innerHTML = 'Copied!';
        setTimeout(function(){ btn.innerHTML = orig; }, 1500);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(onSuccess).catch(function() {
            fallbackCopy(text);
            onSuccess();
        });
    } else {
        fallbackCopy(text);
        onSuccess();
    }
}
function fallbackCopy(text) {
    var ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
}
""")
    )
)


# -- UI -----------------------------------------------------------------------

example_btn = (
    ui.input_action_button(
        "load_example",
        "Load Example Data",
        class_="btn-outline-info w-100",
        icon=tags.i(class_="fa fa-flask"),
    )
    if EXAMPLE_FILE.exists()
    else None
)

app_ui = ui.page_sidebar(
    ui.sidebar(
        ui.accordion(
            ui.accordion_panel(
                "AWS Connection",
                ui.input_text("aws_region", "Region", value=os.environ.get("AWS_DEFAULT_REGION", "us-east-1")),
                ui.input_text("aws_profile", "Profile (optional)", value=os.environ.get("AWS_PROFILE", "")),
                ui.input_text("aws_access_key", "Access Key ID (optional)", value=""),
                ui.input_password("aws_secret_key", "Secret Access Key (optional)", value=""),
                ui.input_text("aws_session_token", "Session Token (optional)", value=""),
                ui.help_text("Leave credentials blank to use the default credential chain (env vars, profile, IAM role)."),
                icon=tags.i(class_="fa fa-cloud"),
            ),
            open=False,
        ),
        ui.input_checkbox_group(
            "severity_filter",
            "Severity",
            choices=SEVERITY_LEVELS,
            selected=["CRITICAL", "HIGH", "MEDIUM"],
        ),
        ui.input_checkbox_group(
            "status_filter",
            "Status",
            choices=["ACTIVE", "SUPPRESSED", "CLOSED"],
            selected=["ACTIVE"],
        ),
        ui.input_checkbox_group(
            "resource_type_filter",
            "Resource Type",
            choices=RESOURCE_TYPE_CHOICES,
            selected=[],
        ),
        ui.help_text("Leave Resource Type empty to fetch all types."),
        ui.input_checkbox("in_use_filter", "Container images in use (ECS/EKS only)", value=False),
        tags.hr(),
        ui.input_radio_buttons(
            "fetch_mode",
            "Fetch Mode",
            choices={"api": "Fetch via API", "cli": "Generate AWS CLI Command"},
            selected="api",
            inline=True,
        ),
        ui.input_action_button("fetch_btn", "Fetch Findings", class_="btn-primary w-100"),
        ui.input_action_button("cli_btn", "Generate CLI Command", class_="btn-info w-100", style_="display:none;"),
        ui.input_action_button("cancel_btn", "Cancel", class_="btn-danger w-100 mt-2", style_="display:none;"),
        ui.download_button("download_csv", "Export CSV", class_="btn-outline-secondary w-100 mt-2"),
        tags.hr(),
        ui.input_file("upload_json", "Upload Findings JSON", accept=[".json"]),
        ui.help_text("Upload a JSON file from the AWS CLI command above."),
        example_btn,
        tags.hr(),
        ui.output_text("fetch_status_short"),
        title="Controls",
        width=300,
    ),
    CUSTOM_JS,
    tags.head(tags.link(rel="icon", type="image/x-icon", href="/favicon.ico")),
    ui.layout_columns(
        ui.value_box(
            "Total Findings",
            ui.output_text("total_count"),
            showcase=tags.i(class_="fa fa-magnifying-glass"),
            theme="primary",
        ),
        ui.value_box(
            "Critical",
            ui.output_text("critical_count"),
            showcase=tags.i(class_="fa fa-circle-exclamation"),
            theme="danger",
        ),
        ui.value_box(
            "High",
            ui.output_text("high_count"),
            showcase=tags.i(class_="fa fa-triangle-exclamation"),
            theme="warning",
        ),
        ui.value_box(
            "Fix Available",
            ui.output_text("fix_count"),
            showcase=tags.i(class_="fa fa-wrench"),
            theme="success",
        ),
        col_widths=[3, 3, 3, 3],
    ),
    ui.navset_card_tab(
        ui.nav_panel(
            "Findings Table",
            ui.card_body(
                ui.output_data_frame("findings_table"),
                class_="p-2",
            ),
        ),
        ui.nav_panel(
            "Severity Breakdown",
            ui.layout_columns(
                ui.card(
                    ui.card_header("Findings by Severity"),
                    ui.output_plot("severity_plot", height="350px"),
                ),
                ui.card(
                    ui.card_header("Findings by Resource Type"),
                    ui.output_plot("resource_plot", height="350px"),
                ),
                col_widths=[6, 6],
            ),
        ),
        ui.nav_panel(
            "Timeline",
            ui.card(
                ui.card_header("Findings Over Time"),
                ui.output_plot("timeline_plot", height="400px"),
            ),
        ),
        ui.nav_panel(
            "Exploit & Fix Status",
            ui.layout_columns(
                ui.card(
                    ui.card_header("Fix Available"),
                    ui.output_plot("fix_plot", height="300px"),
                ),
                ui.card(
                    ui.card_header("Exploit Available"),
                    ui.output_plot("exploit_plot", height="300px"),
                ),
                col_widths=[6, 6],
            ),
        ),
        title="Analysis",
    ),
    ui.card(
        ui.card_header(
            tags.div(
                "Fetch Log",
                ui.input_action_button("clear_log", "Clear", class_="btn-sm btn-outline-secondary"),
                class_="d-flex justify-content-between align-items-center",
            ),
        ),
        ui.card_body(
            tags.div(
                ui.output_ui("fetch_log_output"),
                id="log_container",
                style=(
                    "height:180px; overflow-y:auto; padding:10px; "
                    "font-family:'SFMono-Regular',Consolas,'Liberation Mono',Menlo,monospace; "
                    "font-size:0.82rem; background-color:#1e1e1e; color:#d4d4d4;"
                ),
            ),
            class_="p-0",
        ),
    ),
    title=TagList(
        "AWS Inspector Findings",
        tags.a(
            tags.i(class_="fab fa-github", style="margin-left:10px; font-size:0.9em;"),
            href="https://github.com/statik/inspector-findings",
            target="_blank",
            title="View on GitHub",
            style="color:inherit; text-decoration:none;",
        ),
    ),
    theme=ui.Theme("flatly"),
)


# -- Server -------------------------------------------------------------------


def server(input: Inputs, output: Outputs, session: Session):
    # -- Reactive state --
    findings_rv: reactive.Value[pd.DataFrame] = reactive.value(pd.DataFrame(columns=FINDING_COLUMNS))
    fetch_log_rv: reactive.Value[str] = reactive.value(log_line("Ready. Press 'Fetch Findings' to start."))
    is_fetching: reactive.Value[bool] = reactive.value(False)
    cancel_flag: reactive.Value[bool] = reactive.value(False)

    def append_log(*parts: str):
        fetch_log_rv.set(fetch_log_rv.get() + "\n" + log_line(*parts))

    # -- Button visibility toggling via custom JS message handler --
    async def _toggle_buttons(state: str):
        """Send JS to show/hide fetch/cli/cancel buttons."""
        show = "document.getElementById('{id}').style.display='';"
        hide = "document.getElementById('{id}').style.display='none';"
        if state == "fetching":
            js = hide.format(id="fetch_btn") + hide.format(id="cli_btn") + show.format(id="cancel_btn")
        elif state == "cli":
            js = hide.format(id="fetch_btn") + show.format(id="cli_btn") + hide.format(id="cancel_btn")
        else:  # api
            js = show.format(id="fetch_btn") + hide.format(id="cli_btn") + hide.format(id="cancel_btn")
        await session.send_custom_message("eval_js", js)

    @reactive.effect
    async def _update_button_visibility():
        if is_fetching.get():
            await _toggle_buttons("fetching")
        elif input.fetch_mode() == "cli":
            await _toggle_buttons("cli")
        else:
            await _toggle_buttons("api")

    # -- Clear log --
    @reactive.effect
    @reactive.event(input.clear_log)
    def _clear_log():
        fetch_log_rv.set(log_line("Log cleared."))

    # -- Cancel --
    @reactive.effect
    @reactive.event(input.cancel_btn)
    def _cancel():
        cancel_flag.set(True)
        append_log("Cancellation requested...")

    # -- Build boto3 Inspector2 client --
    def make_client():
        region = input.aws_region().strip()
        profile = input.aws_profile().strip()
        access_key = input.aws_access_key().strip()
        secret_key = input.aws_secret_key().strip()
        session_token = input.aws_session_token().strip()

        kwargs = {}
        if region:
            kwargs["region_name"] = region
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key
            if session_token:
                kwargs["aws_session_token"] = session_token
        elif profile:
            kwargs["profile_name"] = profile

        boto_session = boto3.Session(**kwargs)
        return boto_session.client("inspector2")

    # -- Generate CLI command modal --
    @reactive.effect
    @reactive.event(input.cli_btn)
    def _show_cli_modal():
        cli_parts = build_cli_command(
            region=input.aws_region().strip(),
            profile=input.aws_profile().strip(),
            severities=list(input.severity_filter()),
            statuses=list(input.status_filter()),
            resource_types=list(input.resource_type_filter()),
            ecr_in_use=input.in_use_filter(),
        )
        script = build_python_script(cli_parts)
        cmd_id = f"cli_cmd_{int(datetime.now().timestamp())}"

        m = ui.modal(
            tags.p(
                "Save this as a ",
                tags.code(".py"),
                " file and run with ",
                tags.code("python3 fetch_findings.py"),
                ". It paginates automatically.",
            ),
            tags.p(
                "Then upload the resulting ",
                tags.code("findings.json"),
                " file using the ",
                tags.strong("Upload Findings JSON"),
                " input in the sidebar.",
            ),
            tags.pre(
                script,
                id=cmd_id,
                style=(
                    "background-color:#1e1e1e; color:#d4d4d4; padding:12px; "
                    "border-radius:6px; font-size:0.85em; white-space:pre-wrap; "
                    "word-break:break-all; max-height:450px; overflow-y:auto;"
                ),
            ),
            title=TagList(tags.i(class_="fa fa-terminal"), " AWS CLI Command"),
            size="l",
            easy_close=True,
            footer=TagList(
                tags.button(
                    tags.i(class_="fa fa-copy"),
                    " Copy to Clipboard",
                    type="button",
                    class_="btn btn-primary",
                    onclick=f"copyToClipboard(document.getElementById('{cmd_id}').textContent, event.currentTarget);",
                ),
                ui.modal_button("Close"),
            ),
        )
        ui.modal_show(m)
        append_log("Generated AWS CLI command. Use the modal to copy it.")

    # -- Upload findings JSON --
    @reactive.effect
    @reactive.event(input.upload_json)
    def _upload_json():
        file_infos = input.upload_json()
        if not file_infos:
            return
        file_info = file_infos[0]
        append_log("Reading uploaded file: ", file_info["name"], "...")
        try:
            with open(file_info["datapath"], "r", encoding="utf-8") as f:
                json_text = f.read()
        except Exception as e:
            append_log("ERROR reading file: ", str(e))
            return

        df, error = parse_cli_json(json_text)
        if error:
            append_log("ERROR parsing JSON: ", error)
            ui.notification_show(f"Error parsing JSON: {error}", type="error", duration=8)
            return

        findings_rv.set(df)
        append_log("Loaded ", str(len(df)), " findings from uploaded file.")
        ui.notification_show(
            f"Loaded {len(df)} findings from {file_info['name']}",
            type="message",
            duration=5,
        )

    # -- Load example data --
    @reactive.effect
    @reactive.event(input.load_example)
    def _load_example():
        append_log("Loading example data from example-findings.json...")
        try:
            json_text = EXAMPLE_FILE.read_text(encoding="utf-8")
        except Exception as e:
            append_log("ERROR reading file: ", str(e))
            return
        df, error = parse_cli_json(json_text)
        if error:
            append_log("ERROR parsing JSON: ", error)
            return
        findings_rv.set(df)
        append_log("Loaded ", str(len(df)), " example findings.")

    # -- Fetch via API (async with cancellation) --
    @reactive.effect
    @reactive.event(input.fetch_btn)
    async def _fetch_findings():
        is_fetching.set(True)
        cancel_flag.set(False)

        append_log("Starting fetch (region: ", input.aws_region(), ")...")

        sev_filter = list(input.severity_filter())
        sta_filter = list(input.status_filter())
        res_filter = list(input.resource_type_filter())
        ecr_in_use = input.in_use_filter()

        sev_label = ", ".join(sev_filter) if sev_filter else "ALL"
        sta_label = ", ".join(sta_filter) if sta_filter else "ALL"
        res_label = ", ".join(res_filter) if res_filter else "ALL"
        in_use_label = "; ECR in-use: YES" if ecr_in_use else ""
        append_log(
            "Filters \u2014 severity: ", sev_label,
            "; status: ", sta_label,
            "; resource type: ", res_label,
            in_use_label,
        )

        try:
            client = make_client()
        except Exception as e:
            append_log("ERROR creating client: ", str(e))
            is_fetching.set(False)
            return
        append_log("Inspector2 client created.")

        filter_criteria = build_filter(sev_filter, sta_filter, res_filter, ecr_in_use)

        all_findings: list[dict] = []
        next_token: str | None = None
        page = 0

        while True:
            if cancel_flag.get():
                append_log("Cancelled after ", str(page), " page(s) (", str(len(all_findings)), " findings so far).")
                break

            page += 1
            kwargs: dict = {"filterCriteria": filter_criteria, "maxResults": 100}
            if next_token:
                kwargs["nextToken"] = next_token

            append_log("Requesting page ", str(page), "...")

            try:
                resp = client.list_findings(**kwargs)
            except Exception as e:
                append_log("ERROR on page ", str(page), ": ", str(e))
                break

            page_findings = resp.get("findings", [])
            all_findings.extend(page_findings)
            append_log(
                "Page ", str(page), ": received ", str(len(page_findings)),
                " findings (total so far: ", str(len(all_findings)), ")",
            )

            next_token = resp.get("nextToken")
            if not next_token:
                append_log("Pagination complete. Total raw findings: ", str(len(all_findings)))
                break

            # Yield to the event loop so log updates flush to the UI
            await asyncio.sleep(0)

        if all_findings:
            append_log("Parsing findings into data frame...")
            df = findings_to_df(all_findings)
            findings_rv.set(df)
            suffix = " (cancelled)" if cancel_flag.get() else ""
            append_log("Done. Loaded ", str(len(df)), " findings across ", str(page), " page(s)", suffix, ".")
        else:
            append_log("No findings returned.")

        is_fetching.set(False)

    # -- Value boxes --
    @render.text
    def total_count():
        return str(len(findings_rv.get()))

    @render.text
    def critical_count():
        df = findings_rv.get()
        return str(int((df["severity"] == "CRITICAL").sum())) if len(df) else "0"

    @render.text
    def high_count():
        df = findings_rv.get()
        return str(int((df["severity"] == "HIGH").sum())) if len(df) else "0"

    @render.text
    def fix_count():
        df = findings_rv.get()
        return str(int((df["fixAvailable"] == "YES").sum())) if len(df) else "0"

    # -- Sidebar short status --
    @render.text
    def fetch_status_short():
        if is_fetching.get():
            return "Fetching..."
        df = findings_rv.get()
        return f"{len(df)} findings loaded." if len(df) else "No data loaded."

    # -- Log pane --
    @render.ui
    def fetch_log_output():
        lines = fetch_log_rv.get().split("\n")
        escaped = "<br>".join(
            line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            for line in lines
        )
        return TagList(
            HTML(escaped),
            tags.script(
                HTML(
                    "var el = document.getElementById('log_container'); "
                    "if (el) el.scrollTop = el.scrollHeight;"
                )
            ),
        )

    # -- CSV download --
    @render.download(filename=lambda: f"inspector_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    def download_csv():
        with io.StringIO() as buf:
            findings_rv.get().to_csv(buf, index=False)
            yield buf.getvalue()

    # -- Findings table --
    @render.data_frame
    def findings_table():
        df = findings_rv.get()
        if len(df) == 0:
            return render.DataTable(
                pd.DataFrame({"Message": ["No findings loaded."]}),
                selection_mode="row",
            )
        table_df = df[TABLE_COLUMNS].copy()
        return render.DataTable(
            table_df,
            filters=True,
            selection_mode="row",
            height="600px",
        )

    # -- Row click -> detail modal --
    @reactive.effect
    @reactive.event(findings_table.cell_selection)
    def _show_detail_modal():
        sel = findings_table.cell_selection()
        if sel is None or "rows" not in sel or not sel["rows"]:
            return

        # Map from the viewed (sorted/filtered) row index back to the original data
        view_idx = sel["rows"][0]
        view_rows = findings_table.data_view_rows()

        if view_idx >= len(view_rows):
            return
        orig_idx = view_rows[view_idx]

        df = findings_rv.get()
        if orig_idx >= len(df):
            return
        row = df.iloc[orig_idx]

        sev = row.get("severity", "")
        sev_color = SEVERITY_COLORS.get(sev, "#6c757d")

        # Resource console link
        console_url = aws_console_url(
            row.get("resourceType"), row.get("resourceId"), row.get("resourceRegion")
        )
        resource_id_str = str(row.get("resourceId", ""))
        if console_url:
            resource_id_el = tags.a(
                resource_id_str,
                " ",
                tags.i(class_="fa fa-arrow-up-right-from-square"),
                href=console_url,
                target="_blank",
                style="word-break:break-all;",
            )
        else:
            resource_id_el = tags.code(resource_id_str, style="word-break:break-all;")

        arn_id = f"modal_arn_{int(datetime.now().timestamp())}"
        json_id = f"modal_json_{int(datetime.now().timestamp())}"

        # Serialize row as JSON
        row_dict = {}
        for k, v in row.items():
            if pd.isna(v):
                row_dict[k] = None
            elif hasattr(v, "isoformat"):
                row_dict[k] = v.isoformat()
            else:
                row_dict[k] = v
        row_json = json.dumps(row_dict, indent=2)

        def _val(key: str) -> str:
            v = row.get(key)
            if v is None or (isinstance(v, float) and pd.isna(v)):
                return "\u2014"
            if hasattr(v, "strftime"):
                return v.strftime("%Y-%m-%d %H:%M:%S UTC")
            return str(v)

        # Container image section (conditional)
        container_section = None
        if row.get("resourceType") == "AWS_ECR_CONTAINER_IMAGE":
            container_section = TagList(
                tags.hr(),
                tags.strong(
                    tags.i(class_="fa fa-cube"),
                    " Container Image Details",
                    style="font-size:1em;",
                ),
                tags.div(
                    tags.strong("Repository"), tags.code(_val("imageRepo"), style="word-break:break-all;"),
                    tags.strong("Image Tags"), tags.span(_val("imageTags")),
                    tags.strong("Digest"), tags.code(_val("imageDigest"), style="word-break:break-all;"),
                    tags.strong("Registry ID"), tags.span(_val("imageRegistry")),
                    tags.strong("Architecture"), tags.span(_val("imageArch")),
                    tags.strong("Pushed At"), tags.span(_val("imagePushedAt")),
                    style="display:grid; grid-template-columns:140px 1fr; gap:6px 12px; font-size:0.92em; margin-top:8px;",
                ),
            )

        m = ui.modal(
            tags.div(
                tags.strong("Finding ARN"),
                tags.div(
                    tags.code(str(row.get("findingArn", "")), id=arn_id, style="word-break:break-all; flex:1;"),
                    tags.button(
                        tags.i(class_="fa fa-copy"),
                        " Copy ARN",
                        type="button",
                        class_="btn btn-outline-secondary btn-sm",
                        style="white-space:nowrap; flex-shrink:0;",
                        onclick=f"copyToClipboard(document.getElementById('{arn_id}').innerText, event.currentTarget);",
                    ),
                    style="display:flex; align-items:flex-start; gap:6px;",
                ),
                tags.strong("Status"), tags.span(_val("status")),
                tags.strong("Type"), tags.span(_val("type")),
                tags.strong("Severity"), tags.span(_val("severity"), style=f"color:{sev_color}; font-weight:bold;"),
                tags.strong("Inspector Score"), tags.span(_val("inspectorScore")),
                tags.strong("Account ID"), tags.span(_val("accountId")),
                tags.strong("Resource Type"), tags.span(_val("resourceType")),
                tags.strong("Resource ID"), resource_id_el,
                tags.strong("Region"), tags.span(_val("resourceRegion")),
                tags.strong("Fix Available"), tags.span(_val("fixAvailable")),
                tags.strong("Exploit Available"), tags.span(_val("exploitAvailable")),
                tags.strong("First Observed"), tags.span(_val("firstObservedAt")),
                tags.strong("Last Observed"), tags.span(_val("lastObservedAt")),
                tags.strong("Updated At"), tags.span(_val("updatedAt")),
                style="display:grid; grid-template-columns:140px 1fr; gap:6px 12px; font-size:0.92em;",
            ),
            container_section,
            tags.hr(),
            tags.strong("Description"),
            tags.p(
                _val("description"),
                style="white-space:pre-wrap; font-size:0.9em; margin-top:4px;",
            ),
            tags.pre(row_json, id=json_id, style="display:none;"),
            title=TagList(
                tags.span(
                    sev,
                    style=f"color:white; background-color:{sev_color}; padding:2px 8px; border-radius:4px; font-size:0.85em; margin-right:8px;",
                ),
                str(row.get("title", "")),
            ),
            size="l",
            easy_close=True,
            footer=TagList(
                tags.button(
                    tags.i(class_="fa fa-copy"),
                    " Copy as JSON",
                    type="button",
                    class_="btn btn-outline-secondary",
                    onclick=f"copyToClipboard(document.getElementById('{json_id}').textContent, event.currentTarget);",
                ),
                ui.modal_button("Close"),
            ),
        )
        ui.modal_show(m)

    # -- Plots --
    @render.plot
    def severity_plot():
        import matplotlib.pyplot as plt

        df = findings_rv.get()
        if len(df) == 0:
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            return fig

        counts = df["severity"].value_counts()
        ordered = [s for s in SEVERITY_LEVELS if s in counts.index]
        vals = [counts[s] for s in ordered]
        colors = [SEVERITY_COLORS[s] for s in ordered]

        fig, ax = plt.subplots()
        ax.bar(ordered, vals, color=colors, edgecolor="none")
        ax.set_ylabel("Count")
        fig.tight_layout()
        return fig

    @render.plot
    def resource_plot():
        import matplotlib.pyplot as plt

        df = findings_rv.get()
        if len(df) == 0:
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            return fig

        counts = df["resourceType"].value_counts().head(10)
        fig, ax = plt.subplots()
        ax.barh(counts.index[::-1], counts.values[::-1], color="#2c3e50", edgecolor="none")
        ax.set_xlabel("Count")
        fig.tight_layout()
        return fig

    @render.plot
    def timeline_plot():
        import matplotlib.pyplot as plt

        df = findings_rv.get()
        if len(df) == 0 or df["firstObservedAt"].isna().all():
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            return fig

        daily = df.dropna(subset=["firstObservedAt"]).copy()
        daily["date"] = daily["firstObservedAt"].dt.date
        daily_counts = daily.groupby("date").size().sort_index()

        fig, ax = plt.subplots()
        ax.vlines(daily_counts.index, 0, daily_counts.values, colors="#2c3e50", linewidth=3)
        ax.set_xlabel("Date")
        ax.set_ylabel("New Findings")
        fig.autofmt_xdate()
        fig.tight_layout()
        return fig

    @render.plot
    def fix_plot():
        import matplotlib.pyplot as plt

        df = findings_rv.get()
        if len(df) == 0:
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            return fig

        counts = df["fixAvailable"].fillna("UNKNOWN").value_counts()
        colors = ["#27ae60", "#e74c3c", "#95a5a6"][: len(counts)]
        fig, ax = plt.subplots()
        ax.pie(counts.values, labels=counts.index, colors=colors, startangle=90)
        fig.tight_layout()
        return fig

    @render.plot
    def exploit_plot():
        import matplotlib.pyplot as plt

        df = findings_rv.get()
        if len(df) == 0:
            fig, ax = plt.subplots()
            ax.text(0.5, 0.5, "No data", ha="center", va="center", transform=ax.transAxes)
            ax.set_axis_off()
            return fig

        counts = df["exploitAvailable"].fillna("UNKNOWN").value_counts()
        colors = ["#e74c3c", "#27ae60", "#95a5a6"][: len(counts)]
        fig, ax = plt.subplots()
        ax.pie(counts.values, labels=counts.index, colors=colors, startangle=90)
        fig.tight_layout()
        return fig


app = App(app_ui, server, static_assets=Path(__file__).parent / "www")
