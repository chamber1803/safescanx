import CryptoJS from 'crypto-js';
import { supabase } from './supabase';
import { submitToHybridAnalysis } from './services/hybridAnalysis';

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
  
  // Check file extension vs actual content type
  const expectedType = file.type;
  const extension = file.name.split('.').pop()?.toLowerCase();
  
  // Specific checks for batch files
  if (extension === 'bat' || extension === 'cmd') {
    score += 3; // Higher base score for script files
    
    // Read file content to check for suspicious patterns
    const text = await file.text();
    if (text.includes('while') || text.includes(':loop') || text.includes('goto')) {
      score += 2; // Additional score for potential infinite loops
    }
  }

  if (!expectedType.includes(extension || '')) {
    score += 2;
  }

  // Check file size anomalies
  if (file.size < 100) score += 2;
  if (file.size > 50 * 1024 * 1024) score += 1;
  
  return score;
}

export async function performStaticAnalysis(file: File): Promise<boolean> {
  const suspiciousExtensions = ['exe', 'dll', 'bat', 'cmd', 'vbs', 'js'];
  const extension = file.name.split('.').pop()?.toLowerCase();
  
  if (suspiciousExtensions.includes(extension || '')) {
    // For batch files, perform additional content analysis
    if (extension === 'bat' || extension === 'cmd') {
      const content = await file.text();
      const suspiciousPatterns = [
        'while true',
        ':loop',
        'goto',
        'start /b',
        'shutdown',
        'taskkill',
        'del',
        'rd /s',
        'format'
      ];
      
      return suspiciousPatterns.some(pattern => content.toLowerCase().includes(pattern));
    }
    return true;
  }
  
  return false;
}

export async function performBehavioralAnalysis(file: File): Promise<boolean> {
  try {
    const fileHash = await generateFileHash(file);
    
    // Check if we have any previous behavioral analysis results
    const { data: existingAnalysis } = await supabase
      .from('behavioral_analysis')
      .select('is_malicious')
      .eq('file_hash', fileHash)
      .single();

    if (existingAnalysis) {
      return existingAnalysis.is_malicious;
    }

    // Submit to Hybrid Analysis
    const sandboxResult = await submitToHybridAnalysis(file);
    
    // Store the analysis results
    await supabase
      .from('behavioral_analysis')
      .insert({
        file_hash: fileHash,
        is_malicious: sandboxResult.malicious,
        analysis_details: sandboxResult.details || {
          error: 'Analysis failed or timed out'
        }
      });

    return sandboxResult.malicious;
  } catch (error) {
    console.error('Behavioral analysis error:', error);
    return false;
  }
}