# Djinn: Exploitably verifiable coding problems

Provide a lightweight framework for authoring, validating and distributing programming problems that contain *both* an intended (ground-truth) solution *and* an intentional exploit. Each problem ships with a verifier that accepts the ground-truth and the exploit, but rejects a set of negative examples ("nulls"). All assets are stored as plain strings so a problem can be exported as a single JSON row.

## Installation

```bash
pip install .
```

## Usage

### Create a new problem
```bash
djinn new my-new-problem
```

### Check a problem
```bash
djinn check my-new-problem
```

### Export problems
```bash
djinn export --out dataset.jsonl
``` 
