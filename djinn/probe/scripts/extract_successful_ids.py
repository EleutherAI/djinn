import json
import sys

reference_file = 'generated_metrics/aggregated_qwen_exploits.jsonl'
output_file = 'generated_metrics/qwen_frustration_successful_ids.txt'

successful_ids = set()

try:
    with open(reference_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    obj = json.loads(line)
                    # For this file, we assume all entries are valid exploits as per previous aggregation
                    # But let's be safe and check the flags if present, or just take all
                    # Since we aggregated based on insecure_pass=True and secure_pass=False
                    
                    tid = obj.get('task_id') or obj.get('problem_id')
                    if tid:
                        successful_ids.add(str(tid))
                except json.JSONDecodeError:
                    pass
except FileNotFoundError:
    print(f"Error: Reference file {reference_file} not found")
    sys.exit(1)

if not successful_ids:
    print(f"Error: No successful exploits found in {reference_file}")
    sys.exit(1)

with open(output_file, 'w') as f:
    f.write('\n'.join(sorted(successful_ids)) + '\n')

print(f"Successfully extracted {len(successful_ids)} task IDs to {output_file}")

