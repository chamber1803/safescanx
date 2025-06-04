import CryptoJS from 'crypto-js';

export async function generateFileHash(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result) {
        const wordArray = CryptoJS.lib.WordArray.create(e.target.result as ArrayBuffer);
        const hash = CryptoJS.SHA256(wordArray).toString();
        resolve(hash);
      }
    };
    reader.onerror = (error) => reject(error);
    reader.readAsArrayBuffer(file);
  });
}

export async function performHeuristicAnalysis(file: File): Promise<number> {
  let score = 0;
  
  // Check file extension
  const highRiskExtensions = ['exe', 'dll', 'bat', 'cmd', 'vbs', 'js', 'ps1', 'msi', 'scr', 'com'];
  const mediumRiskExtensions = ['jar', 'hta', 'msc', 'wsf', 'vbe', 'pif'];
  const extension = file.name.split('.').pop()?.toLowerCase();
  
  if (highRiskExtensions.includes(extension || '')) {
    score += 4;
  } else if (mediumRiskExtensions.includes(extension || '')) {
    score += 2;
  }

  // Check file size anomalies
  if (file.size < 1024) score += 3; // Files smaller than 1KB
  if (file.size > 50 * 1024 * 1024) score += 2; // Files larger than 50MB

  // Check file name patterns
  const suspiciousNamePatterns = [
    'crack', 'hack', 'keygen', 'patch', 'generator', 'serial',
    'activate', 'exploit', 'malware', 'trojan', 'virus', 'worm',
    'backdoor', 'rootkit', 'keylog', 'spyware', 'ransom'
  ];

  const fileName = file.name.toLowerCase();
  if (suspiciousNamePatterns.some(pattern => fileName.includes(pattern))) {
    score += 3;
  }

  // Check for obfuscated or unusual names
  if (/^[a-zA-Z0-9]{32,}$/.test(fileName) || // Long random string
      /^[0-9]+$/.test(fileName) || // Only numbers
      fileName.includes('..')) { // Path traversal attempt
    score += 2;
  }

  return Math.min(score, 10);
}

interface BehavioralAnalysisResult {
  isMatch: boolean;
  malicious: boolean;
  details?: {
    suspiciousProcesses: string[];
    networkConnections: string[];
    fileOperations: string[];
    registryOperations: string[];
  };
}

export async function performBehavioralAnalysis(file: File): Promise<BehavioralAnalysisResult> {
  const suspiciousPatterns = {
    processes: [
      'cmd.exe', 'powershell.exe', 'reg.exe', 'rundll32.exe', 'mshta.exe',
      'wscript.exe', 'cscript.exe', 'regsvr32.exe', 'schtasks.exe', 'net.exe',
      'netsh.exe', 'taskkill.exe', 'vssadmin.exe', 'bcdedit.exe', 'wmic.exe'
    ],
    network: [
      'pastebin.com', 'raw.githubusercontent.com', 'ngrok.io', '.onion',
      'temp-mail', 'tempmail', '0x', 'dyndns', 'no-ip.com', '.ru', '.cn',
      'paste.ee', 'requestbin', 'webhook', 'discord.com/api', 'telegram.me'
    ],
    files: [
      'system32', 'windows\\temp', 'appdata\\local', 'programdata',
      'startup', 'windows\\system', 'temp\\', 'recycle.bin',
      'windows\\debug', 'config\\systemprofile'
    ],
    registry: [
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services',
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies',
      'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders'
    ]
  };

  // Read file content
  const content = await file.text();
  
  // Initialize detection arrays
  const detectedProcesses: string[] = [];
  const detectedNetwork: string[] = [];
  const detectedFiles: string[] = [];
  const detectedRegistry: string[] = [];

  // Check for suspicious patterns
  suspiciousPatterns.processes.forEach(process => {
    if (content.toLowerCase().includes(process.toLowerCase())) {
      detectedProcesses.push(process);
    }
  });

  suspiciousPatterns.network.forEach(domain => {
    if (content.toLowerCase().includes(domain.toLowerCase())) {
      detectedNetwork.push(domain);
    }
  });

  suspiciousPatterns.files.forEach(path => {
    if (content.toLowerCase().includes(path.toLowerCase())) {
      detectedFiles.push(path);
    }
  });

  suspiciousPatterns.registry.forEach(key => {
    if (content.toLowerCase().includes(key.toLowerCase())) {
      detectedRegistry.push(key);
    }
  });

  // Additional checks for encoded/obfuscated content
  const base64Pattern = /[A-Za-z0-9+/]{50,}={0,2}/g;
  const hexPattern = /[0-9A-Fa-f]{50,}/g;
  
  if (base64Pattern.test(content)) {
    detectedFiles.push('Base64 encoded content detected');
  }
  
  if (hexPattern.test(content)) {
    detectedFiles.push('Hex encoded content detected');
  }

  // Check for common malware strings
  const malwareStrings = [
    'CreateRemoteThread',
    'VirtualAlloc',
    'WriteProcessMemory',
    'CreateProcess',
    'WinExec',
    'ShellExecute',
    'Downloads\\',
    'GetAsyncKeyState',
    'CreateMutex'
  ];

  malwareStrings.forEach(str => {
    if (content.includes(str)) {
      detectedProcesses.push(`Suspicious API call: ${str}`);
    }
  });

  // Determine if file is potentially malicious
  const isMalicious = 
    detectedProcesses.length > 0 ||
    detectedNetwork.length > 0 ||
    detectedFiles.length > 0 ||
    detectedRegistry.length > 0;

  return {
    isMatch: true,
    malicious: isMalicious,
    details: {
      suspiciousProcesses: detectedProcesses,
      networkConnections: detectedNetwork,
      fileOperations: detectedFiles,
      registryOperations: detectedRegistry
    }
  };
}