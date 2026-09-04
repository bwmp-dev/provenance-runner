# Runner repository instructions

- Treat every customer JAR and its output as hostile input.
- Keep environment providers generic; Paper is the only v1 implementation.
- Hosted execution must use gVisor, non-root processes, isolated namespaces, dropped capabilities, quotas, timeouts, bounded output, and guaranteed cleanup.
- Effective network permission is the intersection of platform, runner, organization, project, and job policy.
- Verify artifact and dependency hashes after download and before execution.
- Never accept database, Temporal, marketplace, or platform-management credentials.
- Distinguish infrastructure failures from plugin incompatibility.
- Keep complete logs in object storage; send only bounded live batches and structured results through the gateway.
- Hostile fixture tests run only in an explicitly prepared disposable Linux environment.
- Never request, tag, invoke, or mention an external automated pull-request reviewer unless the user explicitly names and authorizes that exact service.
- Claude Code invoked locally through `bin/claude-review` is an authorized in-harness independent reviewer. It runs read-only and never tags, comments on, or posts to a pull request. External review bots and pull-request tagging remain prohibited.
