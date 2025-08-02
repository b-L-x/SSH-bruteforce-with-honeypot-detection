<!DOCTYPE html>
<html>
<h1 class="center">🔌 SSH Automation Tool</h1>

<p class="center">
    <strong>Multi-threaded SSH command executor</strong> for running bulk commands across multiple servers
</p>

<div class="center">
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python Version">
    <img src="https://img.shields.io/badge/Threads-100%2B-green" alt="Multi-threaded">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    <img src="https://img.shields.io/badge/SSH-Paramiko-red" alt="Paramiko SSH">
</div>

![Diagram](https://i.imgur.com/AhhI4eN.png)

<h2>✨ Key Features</h2>

<ul>
  <li>⚡ <strong>High-Speed Execution</strong> with configurable thread pools</li>
  <li>🔓 <strong>Bulk Command Support</strong> run multiple commands per host</li>
  <li>📡 <strong>IP Auto-Detection</strong> extracts IPv4 from any text file</li>
  <li>📊 <strong>Comprehensive Logging</strong> with colored console output</li>
  <li>⏱️ <strong>Timeout Handling</strong> for network resilience</li>
  <li>📁 <strong>Results Export</strong> full session logging</li>
</ul>

<h2>📦 Installation</h2>

<pre><code># Install dependencies
pip install paramiko

# Clone repository (optional)
git clone https://github.com/your-repo/ssh-automation.git
cd ssh-automation</code></pre>

<h2>🚀 Usage Examples</h2>

<h3>Basic Execution</h3>
<pre><code>python ssh_automation.py \
  -ip targets.txt \
  -u admin \
  -p password123 \
  -c "uname -a; df -h" \
  -o results.log</code></pre>

<h3>Advanced Scan</h3>
<pre><code>python ssh_automation.py \
  -ip network_scan.txt \
  -u root \
  -p Admin@1234 \
  -c "apt update; apt upgrade -y" \
  -t 20 \
  -to 10 \
  -o upgrade.log</code></pre>

<h2>⚙️ Configuration Options</h2>

<table>
    <thead>
        <tr>
            <th>Parameter</th>
            <th>Description</th>
            <th>Default</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><code>-ip/--ip-file</code></td>
            <td>File containing IPs or text with embedded IPs</td>
            <td><em>Required</em></td>
        </tr>
        <tr>
            <td><code>-u/--username</code></td>
            <td>SSH username</td>
            <td><em>Required</em></td>
        </tr>
        <tr>
            <td><code>-p/--password</code></td>
            <td>SSH password</td>
            <td><em>Required</em></td>
        </tr>
        <tr>
            <td><code>-c/--commands</code></td>
            <td>Commands to execute (semicolon separated)</td>
            <td><em>Required</em></td>
        </tr>
        <tr>
            <td><code>-t/--threads</code></td>
            <td>Number of concurrent workers</td>
            <td>10</td>
        </tr>
        <tr>
            <td><code>-to/--timeout</code></td>
            <td>Connection timeout in seconds</td>
            <td>5</td>
        </tr>
        <tr>
            <td><code>-o/--output</code></td>
            <td>Log file path</td>
            <td><em>Required</em></td>
        </tr>
    </tbody>
</table>

<h2>📝 Sample Output</h2>

<pre><code>[2023-01-01 12:34:56] [+] Connected to 192.168.1.1
[2023-01-01 12:34:56] [*] 192.168.1.1 >>> uname -a
Linux server1 5.4.0-135-generic #152-Ubuntu SMP Wed Nov 23 20:19:22 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
[2023-01-01 12:34:57] [*] 192.168.1.1 >>> df -h
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   15G   33G  32% /
[2023-01-01 12:34:58] [-] Auth failed on 192.168.1.2</code></pre>

<h2>🛠️ Technical Implementation</h2>

<h3>Core Components</h3>
<pre><code class="language-python">class ResultLogger:
    """Handles both console and file logging with colors"""
    
class SSHWorker:
    """Thread worker for parallel SSH execution"""

IPV4_PATTERN = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(...)</code></pre>

<h3>Execution Flow</h3>
<ol>
    <li>Extract IPs from input file</li>
    <li>Initialize thread pool</li>
    <li>Establish SSH connections</li>
    <li>Execute commands sequentially</li>
    <li>Log all output and errors</li>
</ol>

<h2>📜 License</h2>
<p>MIT License - See <a href="LICENSE">LICENSE</a> for details.</p>

<div class="notice">
    <p>⚠️ <strong>Legal Notice:</strong> Use only on systems you own or have permission to access. Unauthorized access is prohibited.</p>
</div>

<h2>📞 Support</h2>
<p>Report issues at <a href="https://github.com/your-repo/ssh-automation/issues">GitHub Issues</a></p>
</body>
</html>