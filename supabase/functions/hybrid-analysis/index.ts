import { MultipartReader } from "https://deno.land/std@0.208.0/mime/multipart.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
};

interface HybridAnalysisError {
  error: string;
  status?: number;
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const endpoint = url.searchParams.get('endpoint');
    
    if (!endpoint) {
      throw new Error('Missing endpoint parameter');
    }

    const API_KEY = Deno.env.get('HYBRID_ANALYSIS_API_KEY');
    if (!API_KEY) {
      throw new Error('Hybrid Analysis API key not configured');
    }

    const baseUrl = 'https://www.hybrid-analysis.com/api/v2';
    const apiUrl = `${baseUrl}/${endpoint}`;

    // Common headers for all requests
    const headers = {
      'api-key': API_KEY,
      'User-Agent': 'Hybrid-Analysis-JavaScript/1.0',
      'accept': 'application/json'
    };

    let response;

    if (req.method === 'POST' && endpoint === 'submit/file') {
      // Handle file upload
      const contentType = req.headers.get('content-type');
      if (!contentType?.includes('multipart/form-data')) {
        throw new Error('Invalid content type for file upload');
      }

      // Forward the multipart form data
      response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          ...headers,
          'Content-Type': req.headers.get('content-type') || ''
        },
        body: req.body
      });
    } else {
      // Handle other API requests
      response = await fetch(apiUrl, {
        method: req.method,
        headers: {
          ...headers,
          'Content-Type': 'application/json'
        },
        ...(req.method === 'POST' && { body: req.body })
      });
    }

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(errorData.error || `HTTP error! status: ${response.status}`);
    }

    const data = await response.json();

    return new Response(JSON.stringify(data), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    console.error('Hybrid Analysis error:', error);

    const errorResponse: HybridAnalysisError = {
      error: error instanceof Error ? error.message : 'Unknown error occurred',
      status: 500
    };

    return new Response(JSON.stringify(errorResponse), {
      status: errorResponse.status || 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});