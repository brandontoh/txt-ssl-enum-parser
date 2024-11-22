# txt-ssl-enum-parser

## Installation

```
pip install beautifulsoup4
pip install requests
```

## Usage

Help menu:

```
python ssl-enum-parser.py --help
```

Basic usage:

```
python ssl-enum-parser.py --dir <DIR WITH NMAP FILES> --out <OUTPUT CSV PATH>
```

```
python ssl-enum-parser.py --file <SINGLE NMAP FILE> --out <OUTPUT CSV PATH>
```

Note: you can also choose to leave out the --out argument, it will default to output.csv in the current directory

Note: the file search in directory is not recursive, so it only parses nmap in that directory

Note: if your directory has space, remember to wrap with single/double quote

By default, when using the --dir argument, the script searches for "ssl-enum-cipher" in the filename and parses them, so if your ssl ciphers nmap dont have this naming and uses someother naming convention, you can make use of this keyword argument to change it:

```
python ssl-enum-parser.py --dir <DIR WITH NMAP FILES> --out <OUTPUT CSV PATH> --keyword "all-my-ssl-enum-ciphers-have-this-special-keyword"
```

## What this script tries to do

- extract all tls ciphers
- search them in ciphersuite.info (with caching, so don't search the same cipher twice)
- for each cipher, extract the status (secure, weak, insecure) and the part that is weak (cbc, dhe, rsa, etc.)
- output in csv
