# ArmorCode SDK (ac-sdk-v2)

Lightweight SDK for the ArmorCode REST API, available in **Python** and **Ruby**.

## Language Support

| | Python | Ruby |
|---|---|---|
| Location | `armorcode/` | `ruby/` |
| Entry point | `ArmorCodeClient` | `Armorcode::Client` |
| Dependency | `requests` | `faraday`, `faraday-retry` |
| Method parity | Full | Full |

Both SDKs share the same method names, parameter conventions, and env file format.

---

## Python

### Quick Start

1. Create an `env` file in the repo root (see [Env File Format](#env-file-format) below).
2. Install dependencies:

   ```bash
   pip install requests
   ```

3. Run the demo:

   ```bash
   python examples/demo.py
   ```

4. Or use the SDK directly:

   ```python
   from armorcode import ArmorCodeClient

   ac = ArmorCodeClient.from_env("env")

   findings = ac.get_findings(severities=["Critical", "High"], days_back=14)
   for repo, count in ac.list_repos():
       print(f"{repo}: {count}")
   ```

---

## Ruby

### Quick Start

1. Create an `env` file in the repo root (see [Env File Format](#env-file-format) below).
2. Install dependencies:

   ```bash
   cd ruby
   bundle install
   ```

3. Run the demo:

   ```bash
   ruby ruby/examples/demo.rb
   ```

   To use a different env file:

   ```bash
   AC_ENV=/path/to/env ruby ruby/examples/demo.rb
   ```

4. Or use the SDK directly:

   ```ruby
   require_relative "ruby/lib/armorcode"

   ac = Armorcode::Client.from_env("env")

   findings = ac.get_findings(severities: ["Critical", "High"], days_back: 14)
   ac.list_repos(findings: findings).each do |repo, count|
     puts "#{repo}: #{count}"
   end
   ```

---

## Env File Format

Both SDKs read the same env file format:

```
TENANT_URL=https://my-tenant-url
API_TOKEN=<api-token>
```

`TENANT_URL` can be a bare hostname or a full `https://` URL. By default both SDKs look for a file named `env` in the working directory. Override with the `AC_ENV` environment variable.

---

## Documentation

- **[docs/methods.md](docs/methods.md)** — complete method reference, grouped by resource
- **[docs/findings.md](docs/findings.md)** — finding filters, filter cheatsheet, 10K limit & auto-chunking
- **[examples/demo.py](examples/demo.py)** — Python demo script
- **[ruby/examples/demo.rb](ruby/examples/demo.rb)** — Ruby demo script
