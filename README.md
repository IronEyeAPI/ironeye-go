# IronEye for Go

The official Go client for the [IronEye](https://ironeye.org) API: document
analysis over bytes you send, and normalised collection from public sources,
behind one key.

```sh
go get github.com/IronEyeAPI/ironeye-go
```

## Features

- Every analysis route, the async job path with `AwaitJob`, the collection
  catalogue and the data-subject-rights endpoints.
- `context.Context` on every call: cancelling it cancels the pending retry too.
- `errors.Is` against a sentinel per refusal family.
- Retries on the server's own `Retryable` flag, honouring `Retry-After`.
- `log/slog`, silent until you pass a logger. No credential, no payload.
- One module, no third-party dependencies.

Full documentation, including every endpoint and every option, is at
**https://ironeye.org/docs/sdk/go**.

---

Direct Softworks · [MIT](LICENSE) · issues and pull requests welcome
