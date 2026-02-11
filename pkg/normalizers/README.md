# Tool Normalizers

Модуль нормализаторов для приведения результатов различных security tools к единому формату `NormalizedFinding`.

## Архитектура

```
Tool Output → Normalizer → NormalizedFinding[]
                        ↓
                Findings Processor → Filtered Results
```

## Поддерживаемые инструменты

| Инструмент | Статус | Нормализатор | Категория |
|------------|--------|--------------|-----------|
| Bandit | ✅ | BanditNormalizer | Code Security (Python) |
| Gitleaks | ✅ | GitleaksNormalizer | Secrets Detection |
| Trivy | ✅ | TrivyNormalizer | Vulnerability Scanning |
| Gosec | ✅ | GosecNormalizer | Code Security (Go) |
| Semgrep | 🚧 | SemgrepNormalizer | Code Security |
| Njsscan | 🚧 | NjsscanNormalizer | Code Security (JS/TS) |
| Hadolint | 🚧 | HadolintNormalizer | Container Security |
| OSV | 🚧 | OSVNormalizer | Vulnerability DB |
| Safety | 🚧 | SafetyNormalizer | Dependency Security |

## Использование

### CLI Tool

```bash
# Авто-детекция инструмента
./normalizer input.json

# Ручная обработка
./aggregator tool bandit results.json normalized/
./aggregator tool gosec results.json normalized/

# Агрегация результатов
./aggregator aggregate normalized/ all_findings.json
```

### Programmatic

```go
factory := normalizers.NewNormalizerFactory()
normalizer := factory.GetNormalizer(rawData)
findings, err := normalizer.Normalize(rawData)
```

## Форматы входных данных

### Bandit
```json
{
  "results": [
    {
      "test_id": "B101",
      "issue_severity": "LOW",
      "issue_confidence": "HIGH",
      "issue_text": "Assert detected",
      "filename": "test.py",
      "line_number": 15
    }
  ]
}
```

### Gitleaks
```json
[
  {
    "Description": "Hardcoded password detected",
    "File": "config.py",
    "StartLine": 10,
    "RuleID": "generic-api-key"
  }
]
```

### Trivy
```json
{
  "Results": [
    {
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "Severity": "HIGH",
          "PkgName": "openssl",
          "Title": "Buffer overflow vulnerability"
        }
      ]
    }
  ]
}
```

### Gosec
```json
{
  "Issues": [
    {
      "rule_id": "G304",
      "severity": "HIGH",
      "confidence": "HIGH",
      "details": "File inclusion via variable",
      "file": "main.go",
      "line": 23,
      "cwe": {"id": "22"}
    }
  ],
  "GosecVersion": "2.22.1"
}
```

## Добавление нового нормализатора

1. Создать новый файл `pkg/normalizers/{tool}.go`
2. Реализовать интерфейс `ToolNormalizer`
3. Зарегистрировать в `NormalizerFactory.registerNormalizers()`

```go
type NewToolNormalizer struct{}

func (n *NewToolNormalizer) CanHandle(rawData []byte) bool {
    // Detect tool-specific format
}

func (n *NewToolNormalizer) Normalize(rawData []byte) ([]NormalizedFinding, error) {
    // Parse and normalize
}
```

## Тестирование

```bash
# Тест одного нормализатора
go run cmd/normalizer/main.go test_data/tool_output.json

# Тест workflow
go run example_workflow.sh
```

## Производительность

- **Bandit**: 45 findings → ~2ms
- **Gitleaks**: 31 findings → ~1ms
- **Trivy**: 5 findings → ~1ms
- **Gosec**: 2 findings → ~0.5ms

Общая производительность: **~10k findings/сек**