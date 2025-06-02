const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, GET, OPTIONS'
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const url = new URL(req.url);
    const endpoint = url.searchParams.get('endpoint') || 'key/current';
    const method = req.method;
    const API_KEY = Deno.env.get('HYBRID_ANALYSIS_API_KEY');

    if (!API_KEY) {
      throw new Error('Hybrid Analysis API key not configured');
    }

    const response = await fetch(`https://www.hybrid-analysis.com/api/v2/${endpoint}`, {
      method,
      headers: {
        'api-key': API_KEY,
        'User-Agent': 'Hybrid-Analysis-JavaScript/1.0',
        'accept': 'application/json',
        ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {})
      },
      ...(method === 'POST' ? { body: req.body } : {})
    });

    const data = await response.json();

    return new Response(JSON.stringify(data), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    });
  }
});