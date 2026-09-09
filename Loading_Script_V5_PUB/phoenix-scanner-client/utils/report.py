"""Report generation utility"""

import json
from datetime import datetime
from typing import List, Dict, Any
from pathlib import Path


def generate_report(results: List[Dict[str, Any]], output_file: str):
    """
    Generate a comprehensive report of upload results.
    
    Args:
        results: List of upload results
        output_file: Output file path
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    successful = [r for r in results if r.get('success')]
    failed = [r for r in results if not r.get('success')]
    
    # Determine format from extension
    ext = Path(output_file).suffix.lower()
    
    if ext == '.json':
        # JSON report
        report = {
            'timestamp': timestamp,
            'summary': {
                'total': len(results),
                'successful': len(successful),
                'failed': len(failed),
                'success_rate': len(successful) / len(results) * 100 if results else 0
            },
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
    
    elif ext == '.html':
        # HTML report
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Phoenix Scanner Upload Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; }}
        .summary {{ background: #ecf0f1; padding: 15px; margin: 20px 0; }}
        .success {{ color: #27ae60; }}
        .failure {{ color: #e74c3c; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background: #34495e; color: white; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Phoenix Scanner Upload Report</h1>
        <p>Generated: {timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>Total files: {len(results)}</p>
        <p class="success">Successful: {len(successful)}</p>
        <p class="failure">Failed: {len(failed)}</p>
        <p>Success rate: {len(successful)/len(results)*100:.1f}%</p>
    </div>
    
    <h2>Results</h2>
    <table>
        <tr>
            <th>File</th>
            <th>Status</th>
            <th>Job ID</th>
            <th>Details</th>
        </tr>
"""
        for r in results:
            status = "✓ Success" if r.get('success') else "✗ Failed"
            status_class = "success" if r.get('success') else "failure"
            job_id = r.get('job_id', 'N/A')
            error = r.get('error', '')
            
            html += f"""
        <tr>
            <td>{r.get('file', 'Unknown')}</td>
            <td class="{status_class}">{status}</td>
            <td>{job_id}</td>
            <td>{error}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        with open(output_file, 'w') as f:
            f.write(html)
    
    else:
        # Text report
        lines = []
        lines.append("=" * 80)
        lines.append("PHOENIX SCANNER UPLOAD REPORT")
        lines.append("=" * 80)
        lines.append(f"Generated: {timestamp}")
        lines.append("")
        lines.append("SUMMARY:")
        lines.append(f"  Total files: {len(results)}")
        lines.append(f"  Successful: {len(successful)}")
        lines.append(f"  Failed: {len(failed)}")
        if results:
            lines.append(f"  Success rate: {len(successful)/len(results)*100:.1f}%")
        lines.append("")
        
        if successful:
            lines.append("✓ SUCCESSFUL UPLOADS:")
            lines.append("-" * 40)
            for r in successful:
                lines.append(f"  File: {r.get('file')}")
                lines.append(f"  Job ID: {r.get('job_id')}")
                if r.get('final_status'):
                    lines.append(f"  Final status: {r.get('final_status')}")
                lines.append("")
        
        if failed:
            lines.append("✗ FAILED UPLOADS:")
            lines.append("-" * 40)
            for r in failed:
                lines.append(f"  File: {r.get('file')}")
                lines.append(f"  Error: {r.get('error')}")
                lines.append("")
        
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines))



