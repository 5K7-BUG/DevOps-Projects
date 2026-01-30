package trivy.security

default allow = true

critical_count := count([
  v |
  v := input.Results[_].Vulnerabilities[_]
  v.Severity == "CRITICAL"
])

deny[msg] {
  critical_count > 0
  msg := sprintf("Build blocked: %d CRITICAL vulnerabilities found", [critical_count])
}

allow {
  critical_count == 0
}
