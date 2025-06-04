import React, { useState } from 'react';
import { Shield } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { ScanResults } from './components/ScanResults';
import { generateFileHash, performHeuristicAnalysis, performBehavioralAnalysis } from './lib/scanners';

export default function App() {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<any>(null);

  const handleFileSelect = async (file: File) => {
    setScanning(true);
    try {
      const [fileHash, heuristicScore, behavioralAnalysis] = await Promise.all([
        generateFileHash(file),
        performHeuristicAnalysis(file),
        performBehavioralAnalysis(file)
      ]);

      setResults({
        fileHash,
        heuristicScore,
        fileName: file.name,
        fileSize: file.size,
        behavioralAnalysis
      });
    } catch (error) {
      console.error('Scan failed:', error);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <div className="flex-grow max-w-4xl mx-auto py-12 px-4 w-full">
        <div className="text-center mb-12">
          <div className="flex justify-center mb-4">
            <Shield className="h-16 w-16 text-blue-600" />
          </div>
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            SafeScanX
          </h1>
          <p className="text-lg text-gray-600">
            File Analysis System
          </p>
        </div>

        {!results && !scanning && (
          <FileUpload onFileSelect={handleFileSelect} />
        )}

        {scanning && (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mx-auto"></div>
            <p className="mt-4 text-gray-600">Analyzing file...</p>
          </div>
        )}

        {results && !scanning && (
          <ScanResults results={results} />
        )}
      </div>
      
      <footer className="bg-gray-800 text-white py-4 text-center">
        <p className="text-sm">
          © {new Date().getFullYear()} SafeScanX. All rights reserved.
        </p>
      </footer>
    </div>
  );
}