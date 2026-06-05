# QX Scripts

Quantumult X scripts and rewrite resources for personal sign-in automation.

## Files

- `qx/nodeseek_qx.js`: NodeSeek scheduled sign-in and request-header capture script.
- `qx/nodeseek_qx_rewrite.conf`: NodeSeek rewrite resource switch for capturing login state.
- `qx/52pj_qx.js`: 52pojie scheduled check-in helper and request-header capture script.
- `qx/52pj_qx_rewrite.conf`: 52pojie rewrite resource switch for capturing login state.

## Quantumult X

Add the rewrite resources from GitHub Raw URL:

```text
https://raw.githubusercontent.com/<user>/<repo>/main/qx/nodeseek_qx_rewrite.conf
https://raw.githubusercontent.com/<user>/<repo>/main/qx/52pj_qx_rewrite.conf
```

The JavaScript files must also be available to Quantumult X with the same names used in the rewrite files:

```text
nodeseek_qx.js
52pj_qx.js
```

Cookies and tokens are stored locally in Quantumult X `$prefs`; do not commit captured cookies or secrets.
