package trivy.security

default allow = false

critical_count := count([
  v |
  some i, j
  v := input.Results[i].Vulnerabilities[j]
  v.Severity == "CRITICAL"
])

allow if {
  critical_count == 0
}
