# MTM Diff Viewer Design

## Purpose

MTM Diff Viewer is a portable, static browser tool for reviewing Microsoft Threat Modeling Tool `.tm7` files under Git version control.

The tool focuses on generated threat instances. It compares threat records by the ID assigned by Threat Modeling Tool and shows whether each threat was added, removed, changed, or unchanged.

## Portability

The runtime artifact is intentionally small:

```text
index.html
app.js
styles.css
```

These files can be copied to another machine and opened directly through `index.html`. No build step, package install, or local server is required for normal use.

Threat model files are read through the browser `File` API and processed locally. The app does not upload files or call external services.

## User Workflow

1. Open `index.html` in a modern browser.
2. Select the older `.tm7` file as `Base`.
3. Select the newer `.tm7` file as `Target`.
4. Use status filters to inspect all, added, removed, changed, or unchanged threats.
5. Select a threat in the left pane to compare old and new values in the right pane.

## Threat Extraction

The primary parser looks for the `ThreatInstances` section in `.tm7` XML content.

Each threat instance is extracted from entries matching:

```text
KeyValueOfstringThreat...
```

The comparison key is:

```text
Threat:<Id>
```

The numeric `Id` is taken from the threat instance's `Id` field. List ordering uses this numeric ID so `Threat:10` appears after `Threat:9`.

## Compared Fields

The viewer extracts and compares fields that are useful for threat review:

```text
Threat ID
Type ID
Title
Category
State
Justification
Priority
Interaction
Description
Short Description
Source GUID
Flow GUID
Target GUID
Drawing Surface GUID
```

`Justification` is read from `Justification` when present. For the observed `.tm7` sample format, the value is stored as `StateInformation`, so the parser falls back to that field.

## Diff Model

The app builds a map of threat records for both input files and compares records by ID.

Statuses:

```text
added      Present only in Target
removed    Present only in Base
changed    Present in both, with at least one compared field changed
unchanged  Present in both, with no compared field changes
```

For unchanged threats, the details pane still lists the compared fields with identical before and after values, so users can confirm the reviewed threat.

## UI Layout

The UI is a two-pane reviewer:

- Top area: file selectors, summary counts, filters, and search.
- Left pane: scrollable threat list sorted by numeric threat ID.
- Right pane: scrollable field comparison for the selected threat.

Changed text segments inside old and new field values are highlighted in red so reviewers can spot the precise text-level difference without rereading the whole value.

Empty-state panels are hidden after files are loaded or after a threat is selected.

## XML Handling

Some `.tm7` files may contain content that is not valid XML after decoding, especially when older or differently encoded text appears inside threat notes. To avoid failing the whole file, the threat parser uses scoped text extraction for the `ThreatInstances` section instead of depending only on strict XML DOM parsing.

If `ThreatInstances` cannot be found, the app falls back to a generic object-level parser for XML or JSON-like content. This fallback is secondary and exists only to keep the viewer useful with unexpected files.

## Browser Requirements

Modern Chrome or Edge is recommended.

Plain XML `.tm7` files work through the browser `File` API. ZIP-based `.tm7` files are supported when the browser provides `DecompressionStream` for deflate entries.

## Known Limitations

- The parser is tuned for `.tm7` files that include `ThreatInstances`.
- It does not render the diagram.
- It does not resolve GUIDs into element display names beyond values already present on the threat instance.
- It does not write files or generate reports.
