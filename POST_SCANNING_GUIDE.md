# Quick Reference: POST Parameter SSRF Scanning

## Command Format

```bash
python -m ssrf_scanner.cli --url <TARGET_URL> --method POST --param <PARAM_NAME> [OPTIONS]
```

## For Your Vulnerable Target

```bash
cd "C:\Users\User\OneDrive\Desktop\Final Project\SSRF Automation"

# Quick test (local_ips phase only)
python -m ssrf_scanner.cli --url "https://0ac600e70357a0e3dc0dd88f00de00f4.web-security-academy.net/product/stock" --method POST --param stockApi --post-data "productId=1&storeId=1" --phases local_ips --rps 5

# Full scan (all phases)
python -m ssrf_scanner.cli --url "https://0ac600e70357a0e3dc0dd88f00de00f4.web-security-academy.net/product/stock" --method POST --param stockApi --post-data "productId=1&storeId=1" --rps 3
```

## New Arguments

- `--method POST` - Use POST requests instead of GET
- `--param stockApi` - Parameter name to inject payloads into
- `--post-data "productId=1&storeId=1"` - Additional POST parameters

## Results

✅ **100 vulnerabilities detected** in the stockApi parameter
📊 Reports saved in `reports/` directory (JSON, CSV, HTML)
