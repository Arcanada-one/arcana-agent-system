# Interactive SIGINT readiness repair

Status: source candidate; independent exact-head review, current canonical
admission and resulting-main verification remain required. This change grants
no KC authority and makes no installed or live enforcement claim.

The CLI version line is printed before REPL setup. The real-signal control
therefore waits for the complete normal interactive-session banner, which is
now published after the existing SIGINT registration handshake. A session
whose listener could not register continues with its existing fallback and
a distinct unarmed banner, rather than publishing the normal readiness line.

The control bounds readiness and reaps its own subprocess on every exit path.
It sends a real SIGINT and requires exit 130; signal death is still a failure.
Source-local removed and late registration mutations must fail that same
assertion even when they falsely acknowledge readiness. Late registration is
held by a channel, without timing sleeps. These controls use the offline
session with no prompt, model request or production authority.

Historical source heads and successful, failed and unmeasured receipts remain
preserved. A new receipt and independent review must cover this source head;
the earlier source approval does not extend to the repair.
