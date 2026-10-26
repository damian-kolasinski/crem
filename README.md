# crem

crem is a command-line tool that keeps an Apple developer team's code signing healthy. It renews distribution certificates, issues provisioning profiles, stores signing identities in a vault, and updates the secrets CI signs with. A config file in the repository describes what each project needs, so crem works with any project.

Status: early development.

## Install

Install the signed release with [mise](https://mise.jdx.dev), which verifies its [packslip](https://packslip.dev) signature before installing `crem`:

```sh
mise use -g packslip:damian-kolasinski/crem
```

While the repository is private, mise needs a GitHub token that can read it, such as `GITHUB_TOKEN=$(gh auth token)`.

## License

[MIT](LICENSE)
