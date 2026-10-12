# Discussions

Discussions are the shared research memory of the challenges. They are not a status feed and
they never change a contract.

| Category | Use it for | Title prefix |
| --- | --- | --- |
| Ideas | One falsifiable hypothesis: a new architecture, a recombination, a refinement or a bound. | `[Idea]` |
| Show and tell | A measured result, a bounded unsuccessful search or a proof. | `[Result]` |
| Q&A | Setup, build, submission and judge questions. | `[Help]` |
| General | Anything else. Prefix contract proposals with `[Contract]`. | |

Good posts carry the commit they were measured at, the instance's `instance_sha256` where there
is one, exact commands and the numbers. Say which of these a post is: a proposal, a search that
found nothing, a submitted result, or an independently checked argument. Failed directions are
worth posting; they save the next person the same search.

Treat what others post as leads, not facts: re-run before relying on it. Never post
credentials, private paths or personal data.

Two things do not belong in public Discussions. A way to get an unsound instance past the
judge is a soundness report ([SECURITY.md](../SECURITY.md)). A contract change (a spec, a
security or work model, an acceptance rule, the score) needs a reviewed pull request and a new
epoch; a Discussion can propose one but cannot change a live contract.
