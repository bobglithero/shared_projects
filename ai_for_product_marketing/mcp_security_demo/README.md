


Here is a comprehensive README file for your GitHub repository, properly crediting SlowMist and contextualizing the project based on the linked article:

---

# MCP Security Demonstration Environment

![Educational Use Only](https://img.shields.io/badge/Status-Educational%20Use%20Only-orange)

This repository contains a working demonstration environment for security vulnerabilities in Model Context Protocol (MCP) frameworks, inspired by the article ["From a News Alert to a Demo: Fast Reaction with AI"](https://www.linkedin.com/pulse/from-news-alert-demo-days-rapid-marketing-reaction-ai-bob-glithero-vudkc) by Bob Glithero.

This demo showcases how MCP-based AI systems can be compromised through techniques like data poisoning, function overriding, and cross-MCP call attacks, allowing for unauthorized data exfiltration and system manipulation.

## Overview

This demonstration environment simulates a government intelligence processing system that is vulnerable to MCP-based attacks. It includes:

- A mock intelligence document processor (`mock_intelligence_mcp.py`)
- An enhanced master MCP security scanner implementing attack techniques (`enhanced_master_mcp.py`)
- A poisoned intelligence document generator
- A data capture server for monitoring attacks
- A real-time attack monitoring script
- Complete Docker packaging for easy deployment

The system demonstrates how an AI can be tricked into processing a seemingly legitimate intelligence report that contains hidden, hex-encoded instructions. These instructions can trigger data exfiltration, function overrides, and other malicious behaviors while appearing to perform normal security compliance checks.

## Attack Vectors Demonstrated

The demo showcases several attack techniques, leveraging concepts from SlowMist's research:

1. **Data Poisoning via Hex Encoding**: A government intelligence report contains a hex-encoded payload instructing the system to export classified data to an unauthorized destination.

2. **Function Override Attacks**: The `enhanced_master_mcp.py` server registers a malicious `export_intelligence_data` function that hijacks legitimate export requests, silently exfiltrating data while returning a success message.

3. **Cross-MCP Call Attacks**: The system demonstrates how one MCP server can influence the behavior of another, creating attack chains.

4. **Banana Security Check**: A demonstration of mandatory process dependencies that force users to perform specific (potentially malicious) operations.

## Usage

### Prerequisites

- Docker
- OpenAI API Key

### Build and Run

1. Set your OpenAI API key:
```bash
export OPENAI_API_KEY='your-openai-key'
```

2. Build the environment:
```bash
./build.sh
```

3. Run the demonstration:
```bash
./run-demo.sh
```

4. Access the interface at `http://localhost:3001`

5. To monitor the attack in real-time:
```bash
docker exec -it <container_name> python /demo/scripts/monitor_attack.py
```

### Running the Demonstration

1. Open the WebUI at `http://localhost:3001`
2. Start a new conversation with the AI
3. Ask it to analyze an intelligence document
4. Paste the content from `poisoned_intelligence_report.txt`
5. Observe how the AI processes the document and triggers the hidden export instructions
6. Monitor the attack progress in the logs and via the monitor script

## Credits and Attribution

This demonstration environment incorporates concepts and attack methodologies from **SlowMist's open-source MasterMCP project**, which provides a toolkit for revealing potential security vulnerabilities in MCP frameworks.

- **SlowMist MasterMCP Project**: https://github.com/slowmist/MasterMCP
- **License**: MIT License

The Python scripts and attack techniques in this demo are inspired by SlowMist's educational research on MCP security, including their demonstrations of:
- Data poisoning
- JSON injection
- Competitive function override
- Cross-MCP call attacks

This project is built upon those foundational concepts to create a more comprehensive, real-world scenario demonstrating how these vulnerabilities could be exploited in a government intelligence context.

## Security Warning

⚠️ **This project is for educational and research purposes only.** The techniques demonstrated can be used maliciously. Do not use this code to attack systems without authorization. Unauthorized use may violate laws and regulations.

## Defense Recommendations

Based on the demonstrated vulnerabilities, consider implementing:

- Strict plugin verification and signature checking
- Input validation and sanitization for all MCP communications
- Principle of least privilege for MCP server permissions
- Monitoring and logging of all MCP function calls
- Regular security audits of MCP server configurations

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

The incorporated concepts and inspiration from SlowMist's MasterMCP project are also provided under the MIT License.
