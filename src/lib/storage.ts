import { supabase } from './supabase';

export async function uploadFile(file: File, hash: string) {
  try {
    const filePath = `${hash}/${file.name}`;
    
    // Check if file already exists
    const { data: existingFile } = await supabase.storage
      .from('scanned-files')
      .list(hash);

    // If file exists, return existing path
    if (existingFile && existingFile.length > 0) {
      return { path: filePath };
    }

    // Upload new file
    const { data, error } = await supabase.storage
      .from('scanned-files')
      .upload(filePath, file, {
        cacheControl: '3600',
        upsert: false
      });

    if (error) {
      console.error('Storage upload failed:', error);
      // Return path even if upload fails to prevent blocking the scan process
      return { path: filePath };
    }

    return data;
  } catch (error) {
    console.error('Storage upload failed:', error);
    // Return basic path info to prevent blocking the scan process
    return { path: `${hash}/${file.name}` };
  }
}