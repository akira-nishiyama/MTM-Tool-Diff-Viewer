# MTM Diff Viewer

A local browser viewer for comparing Microsoft Threat Modeling Tool model files when they are versioned with Git. The viewer focuses on generated threat instances, not low-level XML property churn.

## Usage

1. Open `index.html` in a browser.
2. Load the older `.tm7` file into `Base`.
3. Load the newer `.tm7` file into `Target`.
4. Select added, removed, changed, or unchanged threats in the left pane to inspect old and new threat values in the right pane.

Files are processed in the browser and are not uploaded anywhere.

## Git workflow example

To compare a previous revision with the current file:

```powershell
git show HEAD~1:path/to/model.tm7 > old.tm7
Copy-Item path/to/model.tm7 new.tm7
```

Then load `old.tm7` as `Base` and `new.tm7` as `Target`.

## Notes

- The app is static and has no package dependencies.
- Threats are extracted from the `ThreatInstances` section.
- Threat records are matched by the `Id` assigned by Threat Modeling Tool.
- The comparison focuses on meaningful threat fields such as title, category, state, justification, priority, type id, interaction, source, flow, and target.
- If `ThreatInstances` cannot be found, the viewer falls back to object-level diffs where possible.

## Limitations

Threat Modeling Tool versions and templates can store model details differently. The current parser is tuned for `.tm7` files that contain a `ThreatInstances` section with `KeyValueOfstringThreat...` entries.
