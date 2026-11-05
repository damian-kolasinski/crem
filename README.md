# crem

Keep Apple code signing healthy without tying it to a build system. Describe your apps in `crem.yaml`; crem compares that configuration with App Store Connect, creates distribution certificates and provisioning profiles, and publishes matching signing material to CI.

**Status: early development.** Supports App Store and Ad Hoc profiles, local and 1Password vaults, and GitHub Actions repository or environment secrets.

## Integrate with an agent

Open your app's repository in your coding agent and give it this prompt:

```text
Integrate crem (https://github.com/damian-kolasinski/crem) into this project.
Read its README and inspect our targets, bundle IDs, environments, and CI.
Add crem.yaml and wire signing material into our existing build workflow.
Keep credentials outside Git; ask me for missing account details, not secrets.
Validate locally and show dry-run plans. Get my approval before --execute,
changing remote secrets, or removing existing signing setup.
```

## Install

Install the signed release with [mise](https://mise.jdx.dev), which verifies its [packslip](https://packslip.dev) signature before installing `crem`:

```sh
mise use -g packslip:damian-kolasinski/crem
```

## Configure

Commit a `crem.yaml` at your repository root. Commands find the nearest one in the current directory or its parents; use `--config path/to/crem.yaml` to override it.

```yaml
team: ABCDE12345 # Apple Developer team ID, not the API key ID

appStoreConnect:
  keyIdEnv: ASC_KEY_ID
  issuerIdEnv: ASC_ISSUER_ID
  privateKeyEnv: ASC_PRIVATE_KEY # .p8 contents, not a file path

vaults:
  - local: {} # ~/.crem/<team>, outside your repository

profiles:
  - kind: app-store
    name: "{bundleId} AppStore"

apps:
  - name: MyApp
    environments:
      Production: com.example.myapp
      Staging: com.example.myapp.staging
    extensions: [NotificationService]
    secrets:
      app: "PROFILE_{environment}"
      NotificationService: "NOTIFICATION_PROFILE_{environment}"

certificate:
  secrets:
    p12: DISTRIBUTION_P12
    password: DISTRIBUTION_PASSWORD

secretStores:
  - github:
      repository: your-org/your-repo
      # environment: production # omit for repository-level secrets
```

This creates four expected targets: each environment's app and its `.NotificationService` extension. Each target needs every configured profile kind. Profile names must contain `{bundleId}`; templates also support `{app}`, `{environment}`, and `{extension}`. Secret names are uppercased, so the app's secrets above become `PROFILE_PRODUCTION` and `PROFILE_STAGING`.

Provide credentials outside the repository:

- **Apple:** a team App Store Connect API key with access to Certificates, Identifiers & Profiles and permission for the operations you run. Set the three variables named above. For a local key file, replace `privateKeyEnv` with `privateKeyPath: "~/.private_keys/AuthKey_{keyId}.p8"`. Relative paths resolve from `crem.yaml`.
- **GitHub:** a token allowed to read and write Actions secrets for the configured repository or environment. crem tries `GH_TOKEN`, `GITHUB_TOKEN`, then `gh auth token`; set `github.tokenEnv` to use another variable. A workflow's default `GITHUB_TOKEN` is not sufficient to manage Actions secrets.
- **1Password (optional):** install and authenticate the `op` CLI, then add `- 1password: {vault: Signing}` under `vaults`. New identities are saved to every configured vault. Local vaults keep the `.p12` and its password on disk; protect the directory and keep it outside Git.

## Set up or rotate signing

**Commands that change Apple, vaults, or CI secrets only print a plan unless you pass `--execute`.** Plans still contact providers and require credentials. Profile downloads write local files immediately, without `--execute`.

```sh
crem config                  # validate configuration; no network access
crem status                  # inspect Apple signing state and vault coverage
crem apps register           # if configured bundle IDs are missing
crem cert create             # if no suitable identity is held in a vault
crem profiles renew          # preview missing, expiring, or mismatched profiles
crem secrets push            # preview the certificate and App Store profiles for CI
```

Run each needed operation again with `--execute`, in that order, inspecting its plan first. Creating a certificate generates a new private key; an existing Apple certificate alone cannot recover its private key. Apple limits certificate counts and notifies the team when one is created.

Renewal and secret publishing select the distribution certificate that expires last among vault-held identities valid beyond 45 days. Live replaced profiles remain in place; dead profiles with the same name may be deleted before replacement.

`apps register` copies capabilities from the same app or extension in another environment, or from `--capabilities-from BUNDLE_ID`. App Store Connect app records and assignments such as App Groups or iCloud containers still need manual setup in Apple's portal before renewing profiles.

After a successful CI build, preview `crem cleanup`, then use `crem cleanup --execute` to delete eligible dead profiles in the configured apps' bundle ID scope. Live leftovers are kept. Certificate revocation requires the additional `--revoke-certificates` flag; **revoking a certificate can stop installed Ad Hoc builds from launching**.

## Use in CI

`crem secrets push --execute` writes these values to every configured secret store:

| Secret in the example | Value | Build responsibility |
| --- | --- | --- |
| `DISTRIBUTION_P12` | Base64-encoded `.p12` certificate and private key | Decode and import into a temporary signing keychain |
| `DISTRIBUTION_PASSWORD` | Plain-text `.p12` password | Use when importing the identity |
| `PROFILE_PRODUCTION`, `NOTIFICATION_PROFILE_PRODUCTION` (and Staging equivalents) | Base64-encoded App Store `.mobileprovision` files | Decode and install the profiles for the environment being built |

crem checks that every configured profile secret has a live profile containing the selected certificate before writing. Writes across secrets and stores are **not atomic**: if a push fails partway through, pause builds and rerun it before signing. crem does not configure Xcode signing settings or run your build.

For Ad Hoc builds, add this entry to `profiles`:

```yaml
- kind: ad-hoc
  name: "{bundleId} AdHoc"
  devices: all
```

`devices: all` includes all enabled registered iOS devices. Omit it to carry over enabled devices from the previous profile; that requires an existing profile. Ad Hoc profiles are not pushed as secrets. Download and install them on a macOS build runner with Apple credentials:

```sh
crem profiles download --kind ad-hoc --app MyApp --environment Staging --install
```

The download includes the app and its extensions and checks all selected profiles are live before writing. `--install` immediately replaces other installed profiles with the same name and team, including live ones; use `--output DIRECTORY` instead to preserve existing installations. CI still needs the matching signing identity; when rotating Ad Hoc signing, push the new certificate immediately after renewal and before builds resume.

For scheduled health checks, run `crem status --check --json` (add `--skip-vaults` when CI cannot access vaults). Exit code `0` means no action is needed, `3` means signing needs attention; other nonzero codes indicate an error. `--skip-vaults` omits identity coverage checks, so it is not a full signing-readiness check.

After adding a vault, use `crem vault sync` to preview copying identities into it, then `crem vault sync --execute`. For all command options, run `crem <command> --help`.

## License

[MIT](LICENSE)
