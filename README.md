# PolicyLint

PolicyLint is a local-first defensive review tool for IAM-style JSON. It finds public principals, wildcard actions, wildcard resources, control-plane privileges, and broad grants without condition boundaries. It never connects to a cloud account and does not validate or apply a policy.

## Browser dashboard and GitHub Pages

Open `index.html` locally or publish this directory as its own GitHub Pages repository. The included `.github/workflows/pages.yml` deploys the static dashboard from the `main` branch when Pages is configured to use GitHub Actions.

1. Paste an authorized policy or load the synthetic sample.
2. Select **Lint policy**.
3. Review each explainable finding and its remediation hint.
4. Export the JSON report for a review or pull request.

## Docker CLI

```sh
docker build -t policylint .
mkdir -p reports
docker run --rm \
  -v "$PWD/samples:/data:ro" \
  -v "$PWD/reports:/reports" \
  policylint /data/policy.json --output /reports/report.json
```

The sample is synthetic. Review only policies you are authorized to inspect. Findings are provider-agnostic heuristics and should be validated against the exact IAM engine and workload design before deployment.

## Rules and score

Critical findings include public principals and control-plane privileges. High findings include wildcard actions or resources. Review findings cover broad grants without conditions. The score starts at 100 and deducts 25 per critical finding, 15 per high finding, and 7 per review finding.

## License

MIT. See [LICENSE](LICENSE).
