import json, os

with open('results/final/metrics/authoritative_benchmark_metrics.json') as f:
    data = json.load(f)

per_class_summary = {}
for m in data['models']:
    per_class_summary[m] = {
        "precision": data['models'][m].get('per_class_precision', {}),
        "recall": data['models'][m].get('per_class_recall', {}),
        "f1": data['models'][m].get('per_class_f1', {})
    }

os.makedirs('results/final/metrics', exist_ok=True)
with open('results/final/metrics/per_class_metrics.json', 'w') as f:
    json.dump(per_class_summary, f, indent=2)

print('[SUCCESS] Generated results/final/metrics/per_class_metrics.json')
