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
  const suspiciousExtensions = ['exe', 'dll', 'bat', 'cmd', 'vbs', 'js'];
  const extension = file.name.split('.').pop()?.toLowerCase();
  
  if (suspiciousExtensions.includes(extension || '')) {
    score += 3;
  }

  // Check file size anomalies
  if (file.size < 100) score += 2;
  if (file.size > 50 * 1024 * 1024) score += 1;

  // Check file name patterns
  const suspiciousPatterns = ['crack', 'hack', 'keygen', 'patch'];
  if (suspiciousPatterns.some(pattern => file.name.toLowerCase().includes(pattern))) {
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
  // Simulated behavioral analysis
  const suspiciousPatterns = {
    processes: ['cmd.exe', 'powershell.exe', 'reg.exe', 'rundll32.exe'],
    network: ['unknown.com', 'malicious.net', 'suspicious.org'],
    files: ['system32', 'windows\\temp', 'appdata\\local'],
    registry: ['HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run']
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