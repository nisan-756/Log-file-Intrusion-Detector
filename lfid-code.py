import re
import json
import yaml
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def load_config(config_path):
    with open(config_path, 'r') as f:
        if config_path.endswith('.json'):
            return json.load(f)
        elif config_path.endswith(('.yaml', '.yml')):
            return yaml.safe_load(f)
        else:
            raise ValueError("Unsupported config file format")

def parse_log(log_file, rules):
    findings = []

    failed_patterns = rules['rules'].get('failed_login', {}).get('patterns', [])
    sql_patterns = rules['rules'].get('sql_injection', {}).get('patterns', [])
    ip_blacklist = set(rules['rules'].get('ip_blacklist', []))

    with open(log_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            # Failed login (regex)
            for pattern in failed_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append((line_num, 'Failed Login', line.strip()))
                    break

            # SQL Injection (regex)
            for pattern in sql_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append((line_num, 'SQL Injection', line.strip()))
                    break

            # Blacklisted IPs (plain match)
            for ip in ip_blacklist:
                if ip in line:
                    findings.append((line_num, 'Blacklisted IP', line.strip()))
                    break

    return findings

def generate_report(findings, output_file='report.txt'):
    with open(output_file, 'w') as f:
        if not findings:
            f.write(" No suspicious activity found.\n")
        else:
            f.write(" Suspicious Activity Report \n\n")
            for line_num, category, line in findings:
                f.write(f"[Line {line_num}] [{category}] {line}\n")
    return output_file

def send_email_alert(config, findings, report_path):
    if not config.get("email", {}).get("enabled", False) or not findings:
        return

    email_cfg = config["email"]

    msg = MIMEMultipart()
    msg['From'] = email_cfg['sender_email']
    msg['To'] = email_cfg['recipient_email']
    msg['Subject'] = " Intrusion Detected in Log File"

    body = "Suspicious activity was detected in your log file.\n\n"
    body += f"Total Findings: {len(findings)}\n\n"
    body += "See attached report or open the file for details."

    msg.attach(MIMEText(body, 'plain'))

    with open(report_path, 'r') as f:
        report = MIMEText(f.read())
        report.add_header('Content-Disposition', 'attachment', filename='report.txt')
        msg.attach(report)

    try:
        server = smtplib.SMTP(email_cfg['smtp_server'], email_cfg['smtp_port'])
        server.starttls()
        server.login(email_cfg['sender_email'], email_cfg['sender_password'])
        server.send_message(msg)
        server.quit()
        print(" Email alert sent.")
    except Exception as e:
        print(" Failed to send email:", e)

def main(log_path, config_path):
    config = load_config(config_path)
    findings = parse_log(log_path, config)
    report_path = generate_report(findings)
    send_email_alert(config, findings, report_path)

    print(f" Scan complete. Report saved to '{report_path}'")
    if findings:
        print(f" {len(findings)} suspicious entries found.")
    else:
        print(" No threats found.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Log File Intrusion Detector with Regex Support")
    parser.add_argument('--log', required=True, help='Path to the log file')
    parser.add_argument('--config', required=True, help='Path to the config file (YAML or JSON)')
    args = parser.parse_args()

    main(args.log, args.config)