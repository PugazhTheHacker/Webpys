# my_library

`my_library` provides reusable validation and normalization helpers for scanner
targets (domain, IP, URL) and port specifications.

## Install (editable)

```bash
pip install -e .
```

## Example

```python
from my_library import TargetValidator

validator = TargetValidator(default_scheme="https")
result = validator.validate("example.com/login")

if result.valid:
    print(result.normalized_target)  # https://example.com/login
    print(validator.parse_ports("22,80,8000-8002"))  # [22, 80, 8000, 8001, 8002]
```

