# Cloonie

Script to decrypt / import chromium (edge/chrome) cookies.

## Usage

```
usage: cloonie.py [-h] [--infile <infile>] [--inos <inos>] [--inkey <inkey>] [--outos <outos>] [--outfile <outfile>] [--outkey <outkey>] [--domain <domain>] [--debug] [--output]

Decrypt chrome|edge Cookies file and re-encrypt it with a different key

optional arguments:
  -h, --help           show this help message and exit
  --infile <infile>    Cookies input file
  --inos <inos>        Input file OS (windows|linux)
  --inkey <inkey>      Input file key
  --outos <outos>      Output file OS (windows|linux)
  --outfile <outfile>  Cookies output file
  --outkey <outkey>    Output file key
  --domain <domain>    Cookies domain filter
  --debug              Enable debug output
  --output             Ouput cookie value
```

## Examples

### Decrypt Windows Cookies only

`./cloonie.py --inkey <BASE64_KEY> --infile Cookies --output`

### Decrypt Windows Cookies and import them in chromium on Linux

`./cloonie.py --inkey <BASE64_KEY> --infile Cookies --output --outfile ~/.config/chromium/Default/Cookies`

### Decrypt Windows Cookies and import them in chromium on Linux for a specific domain

`./cloonie.py --inkey <BASE64_KEY> --infile Cookies --output --outfile ~/.config/chromium/Default/Cookies --domain microsoft.com`

## Sources

Based on the awesome work of the following tools/scripts authors:

- https://gist.github.com/GramThanos/ff2c42bb961b68e7cc197d6685e06f10
- https://gist.github.com/DakuTree/428e5b737306937628f2944fbfdc4ffc
- https://github.com/crypt0p3g/bof-collection
- https://github.com/rxwx/chlonium
- https://gist.github.com/microo8/d0ecb52ec592971a466a3189287631c7
- https://n8henrie.com/2013/11/use-chromes-cookies-for-easier-downloading-with-python-requests/

