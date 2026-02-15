# Dark Web Monitor

A CLI tool that monitors dark web sources for leaked credentials from your domains.

## Installation

```bash
cd dark-web-monitor
npm install
```

## Usage

```bash
# Single scan
node src/index.js -d example.com -o

# Continuous monitoring
node src/index.js -d example.com,yourcompany.com
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--domains` | `-d` | Comma-separated list of domains |
| `--once` | `-o` | Run once and exit |
| `--interval` | `-i` | Check interval in minutes |
| `--verbose` | `-v` | Verbose output |

## Features

- Monitors breach databases
- Checks leak sites
- Tracks dark web directories
- Detects multiple credential types

## Legal Notice

This tool is for authorized security monitoring only. Ensure you have proper authorization before monitoring any domains or systems.

## License

MIT
