from __future__ import annotations

from dataclasses import dataclass, field

from .utils import normalize_target, parse_ports, split_host_port


@dataclass(slots=True)
class ValidationResult:
    valid: bool
    normalized_target: str | None = None
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    errors: list[str] = field(default_factory=list)


class TargetValidator:
    def __init__(self, default_scheme: str = "https") -> None:
        self.default_scheme = default_scheme

    def validate(self, target: str) -> ValidationResult:
        try:
            normalized = normalize_target(target, default_scheme=self.default_scheme)
            host, port = split_host_port(normalized)
            scheme = normalized.split("://", 1)[0]
            return ValidationResult(
                valid=True,
                normalized_target=normalized,
                host=host,
                port=port,
                scheme=scheme,
            )
        except ValueError as exc:
            return ValidationResult(valid=False, errors=[str(exc)])

    def validate_many(self, targets: list[str]) -> list[ValidationResult]:
        return [self.validate(target) for target in targets]

    def parse_ports(self, ports_spec: str | None) -> list[int]:
        return parse_ports(ports_spec)

