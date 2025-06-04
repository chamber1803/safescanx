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