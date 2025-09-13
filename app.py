from flask import Flask, request, render_template_string
import re
import requests

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Header Forensics</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { font-size: 28px; }
        textarea { width: 100%; height: 200px; }
        pre { background: #fff; padding: 15px; border-radius: 5px; white-space: pre-wrap; }
        .risk { background-color: yellow; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Email Header Forensics</h1>
    <form method="POST">
        <textarea name="headers" placeholder="Paste email headers here...">{{ raw_header }}</textarea><br><br>
        <input type="submit" value="Analyze">
    </form>

    {% if formatted %}
    <h2>Parsed Results:</h2>
    <pre>{{ formatted|safe }}</pre>
    {% endif %}
</body>
</html>
"""

# Risky patterns
risky_keywords = ['.ru', '.zip', 'unknown', 'smtp', 'mail']

def highlight_risks(text):
    for keyword in risky_keywords:
        text = re.sub(f'({re.escape(keyword)})', r'<span class="risk">\1</span>', text, flags=re.IGNORECASE)
    return text

def get_ip_geolocation(ip):
    try:
        res = requests.get(f'https://ipinfo.io/{ip}/json')
        if res.status_code == 200:
            data = res.json()
            return f"{data.get('city', '?')}, {data.get('country', '?')} ({data.get('org', 'Unknown ISP')})"
    except:
        pass
    return "Geolocation unavailable"

@app.route('/', methods=['GET', 'POST'])
def index():
    raw_header = ''
    formatted_result = ''

    if request.method == 'POST':
        raw_header = request.form['headers']
        
        # Parse core headers
        date = re.search(r'^Date:\s*(.*)', raw_header, re.MULTILINE)
        from_ = re.search(r'^From:\s*(.*)', raw_header, re.MULTILINE)
        to = re.search(r'^To:\s*(.*)', raw_header, re.MULTILINE)
        subject = re.search(r'^Subject:\s*(.*)', raw_header, re.MULTILINE)
        msgid = re.search(r'^Message-ID:\s*(.*)', raw_header, re.MULTILINE)

        # Parse Received headers and extract IPs
        received = re.findall(r'^Received:\s*(.*)', raw_header, re.MULTILINE)
        received_info = []
        for line in received:
            ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if ip_match:
                ip = ip_match.group(1)
                geo = get_ip_geolocation(ip)
                received_info.append(f"{line} → 🌍 {geo}")
            else:
                received_info.append(line)

        # Parse SPF, DKIM, DMARC if available
        spf = re.search(r'^Authentication-Results:.*spf=(\w+)', raw_header, re.MULTILINE)
        dkim = re.search(r'^Authentication-Results:.*dkim=(\w+)', raw_header, re.MULTILINE)
        dmarc = re.search(r'^Authentication-Results:.*dmarc=(\w+)', raw_header, re.MULTILINE)

        result = {
            "Date": date.group(1) if date else None,
            "From": from_.group(1) if from_ else None,
            "To": to.group(1) if to else None,
            "Subject": subject.group(1) if subject else None,
            "Message-ID": msgid.group(1) if msgid else None,
            "Received": received_info,
            "SPF": spf.group(1).upper() if spf else "Not found",
            "DKIM": dkim.group(1).upper() if dkim else "Not found",
            "DMARC": dmarc.group(1).upper() if dmarc else "Not found"
        }

        # Format for output
        formatted_result = ""
        for k, v in result.items():
            if isinstance(v, list):
                formatted_result += f"<b>{k}:</b>\n"
                for line in v:
                    formatted_result += f"{highlight_risks(line)}\n"
            else:
                formatted_result += f"<b>{k}:</b> {highlight_risks(str(v))}\n"

    return render_template_string(HTML_TEMPLATE, formatted=formatted_result, raw_header=raw_header)

if __name__ == '__main__':
    app.run(debug=True)

