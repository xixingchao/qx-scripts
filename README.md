# QX Scripts

Quantumult X scripts and rewrite resources for personal sign-in automation.

## Files

- `qx/nodeseek_qx.js`: NodeSeek scheduled sign-in and request-header capture script.
- `qx/nodeseek_qx_rewrite.conf`: NodeSeek rewrite resource switch for capturing login state.
- `qx/52pj_qx.js`: 52pojie scheduled check-in helper and request-header capture script.
- `qx/52pj_qx_rewrite.conf`: 52pojie rewrite resource switch for capturing login state. Keep it separate because this site may trigger WAF/security checks.
- `qx/qx_task.conf`: Quantumult X scheduled task subscription for NodeSeek and 52pojie.
- `qx/task.json`: Quantumult X task repository index for adding tasks from the in-app task gallery.
- `qx/icons/`: Site icons used by the Quantumult X task repository cards.

## Quantumult X

Add the task repository from GitHub URL in Quantumult X `Task Repository`:

```text
https://github.com/xixingchao/qx-scripts/tree/main/qx
```

Add the scheduled task subscription from GitHub Raw URL in Quantumult X `Task` resources:

```text
https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/qx_task.conf
```

Add the rewrite resources from GitHub Raw URL in Quantumult X `Rewrite` resources:

```text
https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/52pj_qx_rewrite.conf
https://raw.githubusercontent.com/xixingchao/qx-scripts/main/qx/nodeseek_qx_rewrite.conf
```

The rewrite resources reference the JavaScript files by GitHub Raw URL, so Quantumult X can fetch the scripts directly.

Cookies and tokens are stored locally in Quantumult X `$prefs`; do not commit captured cookies or secrets.
