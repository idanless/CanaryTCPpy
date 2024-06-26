<!DOCTYPE html>
<html>
<head>

</head>
<body>
  <h1>Welcome to CanaryTCPpy</h1>
  <p>
    CanaryTCPpy is a project inspired by "Canarytokens" that can handle and trigger alerts when scanned by tools like Nmap, Masscan, etc. It utilizes the basic RFC of TCP to create a deception mechanism. By blocking the RST TCP flag, the scanner and hacker remain unaware that the services are fake or the ports are closed.
  </p>
  <p>
    How CanaryTCPpy can help you:
  </p>
  <ol>
    <li>
      Set it up on your WAN (Wide Area Network) and trigger alerts to detect and investigate potential network intrusions.
    </li>
    <li>
      Monitor your network for any suspicious activity by identifying small Docker containers or Linux instances that may indicate attempts to "jump" to other servers.
    </li>
    <li>
      And more! Combine CanaryTCPpy with other security tools to build an active monitoring system, such as an Intrusion Detection System (IDS).
    </li>
  </ol>
  <h2>Example Flow Picture: TCP3 Flow Handling</h2>
  <p>
    Here's an example  picture tcp 3 handshake flow:
  </p>
  <img src="https://media.geeksforgeeks.org/wp-content/uploads/handshake-1.png" alt="TCP3 Flow Handling" width="800">
  <h2>Example Picture: Network Area</h2>
  <p>
    Here's an example picture showcasing the network area:
  </p>
  <img src="https://github.com/idanless/CanaryTCPpy/blob/main/scanpy.JPG?raw=true" alt="Network Area Example" width="800">
  <h2>Example: Nmap Scan Result</h2>
  <p>
    When an attacker scans a system running CanaryTCPpy with Nmap, the fake port is typically marked as yellow, indicating that it appears closed or filtered [you test by any nmap online or local]:
  </p>
  <img src="https://github.com/idanless/CanaryTCPpy/blob/main/nmap.JPG?raw=true" alt="Nmap Scan Result Example" width="800">
  <h2>Getting Started</h2>
  <p>
    To run the project, follow these steps:
  </p>
  <ol>
    <li>
      Clone the repository to your local machine.
    </li>
    <li>
      Install Scapy, preferably using package managers like apt or yum.
    </li>
    <li>
      Run the provided examples in the code.
    </li>
    <li>
     run as sudo or root
    </li>
  </ol>
</body>
</html>
