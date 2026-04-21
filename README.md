# DNSReaper
```text
                 ...
               ;::::;
             ;::::; :;
           ;:::::'   :;
          ;:::::;     ;.
         ,:::::'       ;           OOO\
:::
         ;:::::;       ;         OOOOOOOO
        ,;::::::;     ;'         / OOOOOOO
      ;:::::::::`. ,,,;.        /  / DOOOOOO
    .';:::::::::::::::::;,     /  /     DOOOO
   ,::::::;::::::;;;;::::;,   /  /        DOOO
  ;`::::::`'::::::;;;::::: ,#/  /          DOOO
  :`:::::::`;::::::;;::: ;::#  /            DOOO
  ::`:::::::`;:::::::: ;::::# /              DOO
  `:`:::::::`;:::::: ;::::::#/               DOO
:::
:::
   `:::::`::::::::::::;'`:;::#                O
    `:::::`::::::::;' /  / `:#
:::

        ____  _   _ ____  ____                           
       |  _ \| \ | / ___||  _ \ ___  __ _ _ __   ___ _ __ 
       | | | |  \| \___ \| |_) / _ \/ _` | '_ \ / _ \ '__|
       | |_| | |\  |___) |  _ <  __/ (_| | |_) |  __/ |   
       |____/|_| \_|____/|_| \_\___|\__,_| .__/ \___|_|   
                                         |_|              
```
DNSReaper is a small Python CLI for detecting **CNAME takeover candidates**.

It follows CNAME chains and flags hostnames whose terminal target does **not** resolve to a public A or AAAA record. The output is intended for analyst review; a "candidate" is not automatically a confirmed vulnerability.

## What this public version includes

- Scanning from a text file or Cloudflare API
- CNAME chain walking
- Public vs. non-public IP evaluation
- CSV reporting
- Configurable ignored suffixes

## What was intentionally removed from the original internal version

- Internal DNS API integration
- Company-specific domains and exception lists
- Hard-coded internal IPs and SMTP settings
- Service desk / ticketing automation
- Company CI/CD pipeline wiring
- Personal and corporate identity metadata

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

### 1) Scan from a file

```bash
python dnsreaper.py --source file --input-file sample_domains.txt
```

### 2) Scan from Cloudflare

Create a local `config.json` from `config.example.json`, add your token, then run:

```bash
python dnsreaper.py --source cloudflare --config config.json
```

### 3) Custom resolvers

```bash
python dnsreaper.py \
  --source file \
  --input-file sample_domains.txt \
  --public-resolvers 1.1.1.1,8.8.8.8,9.9.9.9
```

## Output

The tool writes `result.csv` with these columns:

- `hostname`
- `status`
- `reason`
- `chain`

Typical statuses:

- `ok` - final target resolved to at least one public IP
- `candidate` - no public IP found at the end of the chain
- `ignored-rule` - skipped due to ignored suffix config
- `ignored-no-cname` - hostname had no CNAME chain
- `loop` - recursive CNAME loop detected
- `error` - transient lookup or processing failure

## Security notes

- Never commit live tokens or environment-specific config.
- Keep `config.json` in `.gitignore`.
- Review candidates manually before claiming takeover risk.
- Some providers intentionally return private or non-public targets in hybrid environments.

## Suggested public repo structure

```text
DNSReaper/
  dnsreaper.py
  requirements.txt
  config.example.json
  sample_domains.txt
  Dockerfile
  .gitignore
  README.md
```

## License

Pick a license before publishing, for example MIT.
