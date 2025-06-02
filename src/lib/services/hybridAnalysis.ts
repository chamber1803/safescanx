interface HybridAnalysisResult {
  success: boolean;
  malicious: boolean;
  details?: {
    verdict: string;
    threatScore: number;
    suspiciousProcesses: string[];
    networkConnections: string[];
    fileOperations: string[];
    registryOperations: string[];
  };
}

export async function submitToHybridAnalysis(file: File): Promise<HybridAnalysisResult> {
  const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
  
  if (!supabaseUrl) {
    throw new Error('Supabase URL not configured');
  }

  try {
    console.log('Submitting to Hybrid Analysis:', file.name);

    // Verify API access through our proxy
    const infoResponse = await fetch(
      `${supabaseUrl}/functions/v1/malware-check?service=hybrid-analysis&endpoint=key/current`,
      {
        headers: {
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        }
      }
    );

    if (!infoResponse.ok) {
      throw new Error(`API key validation failed: ${infoResponse.status}`);
    }

    // Submit file for analysis
    const formData = new FormData();
    formData.append('file', file);
    formData.append('environment_id', '120');
    formData.append('no_share_third_party', 'true');
    formData.append('no_share_vt', 'true');
    formData.append('allow_community_access', 'false');

    const submitResponse = await fetch(
      `${supabaseUrl}/functions/v1/malware-check?service=hybrid-analysis&endpoint=submit/file`,
      {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
        },
        body: formData
      }
    );

    if (!submitResponse.ok) {
      throw new Error(`File submission failed: ${submitResponse.status}`);
    }

    const submitData = await submitResponse.json();
    if (!submitData.sha256) {
      throw new Error('No SHA256 hash received');
    }

    // Poll for results
    let attempts = 0;
    const maxAttempts = 30;
    const pollingInterval = 10000;

    while (attempts < maxAttempts) {
      console.log(`Polling for results (attempt ${attempts + 1}/${maxAttempts})...`);
      await new Promise(resolve => setTimeout(resolve, pollingInterval));

      const resultResponse = await fetch(
        `${supabaseUrl}/functions/v1/malware-check?service=hybrid-analysis&endpoint=report/${submitData.sha256}/summary`,
        {
          headers: {
            'Authorization': `Bearer ${import.meta.env.VITE_SUPABASE_ANON_KEY}`
          }
        }
      );

      if (!resultResponse.ok) {
        throw new Error(`Failed to retrieve analysis results: ${resultResponse.status}`);
      }

      const result = await resultResponse.json();

      if (result.state === 'SUCCESS') {
        console.log('Analysis completed successfully');
        
        const details = {
          verdict: result.verdict || 'unknown',
          threatScore: result.threat_score || 0,
          suspiciousProcesses: (result.processes || [])
            .filter(p => p.suspicious)
            .map(p => `${p.name} (${p.cmd_line})`),
          networkConnections: (result.network_connections || [])
            .map(c => `${c.protocol}://${c.destination}:${c.port}`),
          fileOperations: (result.file_operations || [])
            .map(f => `${f.operation}: ${f.path}`),
          registryOperations: (result.registry_operations || [])
            .map(r => `${r.operation}: ${r.key}`)
        };

        const isMalicious = 
          (result.threat_score && result.threat_score >= 75) || 
          details.suspiciousProcesses.length > 0 ||
          result.verdict === 'malicious';

        return {
          success: true,
          malicious: isMalicious,
          details
        };
      } else if (result.state === 'ERROR' || result.state === 'FAILED') {
        throw new Error(`Analysis failed: ${result.message || 'Unknown error'}`);
      }

      attempts++;
    }

    throw new Error('Analysis timed out');
  } catch (error) {
    console.error('Hybrid Analysis error:', error);
    return {
      success: false,
      malicious: false,
      details: {
        verdict: 'error',
        threatScore: 0,
        suspiciousProcesses: [],
        networkConnections: [],
        fileOperations: [],
        registryOperations: []
      }
    };
  }
}