import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

let client;

if (!supabaseUrl || !supabaseKey) {
  console.warn('Supabase environment variables are missing. Please click the "Connect to Supabase" button to set them up.');
  // Provide fallback values for development
  const fallbackUrl = 'https://your-project.supabase.co';
  const fallbackKey = 'your-anon-key';
  
  client = createClient(fallbackUrl, fallbackKey);
} else {
  client = createClient(supabaseUrl, supabaseKey);
}

export const supabase = client;