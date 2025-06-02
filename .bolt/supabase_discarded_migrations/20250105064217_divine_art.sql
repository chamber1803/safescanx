/*
  # Storage Configuration

  1. Storage Setup
    - Creates public storage bucket for scanned files
    - Sets up secure access policies
  
  2. Security
    - Limits file uploads to 100MB
    - Enables public read access
*/

-- Create the storage bucket
INSERT INTO storage.buckets (id, name, public)
VALUES ('scanned-files', 'scanned-files', true)
ON CONFLICT (id) DO NOTHING;

-- Set up storage policies
CREATE POLICY "Anyone can upload files"
  ON storage.objects FOR INSERT
  TO public
  WITH CHECK (
    bucket_id = 'scanned-files' AND
    ((metadata->>'size')::int <= 100 * 1024 * 1024)  -- 100MB limit using metadata size
  );

CREATE POLICY "Anyone can read files"
  ON storage.objects FOR SELECT
  TO public
  USING (bucket_id = 'scanned-files');