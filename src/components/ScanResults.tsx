import React from 'react';
import { Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend
} from 'chart.js';

ChartJS.register(ArcElement, Tooltip, Legend);

interface ScanResultsProps {
  results: {
    fileHash: string;
    heuristicScore: number;
    fileName: string;
    fileSize: number;
  };
}

export function ScanResults({ results }: ScanResultsProps) {
  const data = {
    labels: ['Risk Score', 'Safe Score'],
    datasets: [
      {
        data: [results.heuristicScore, 10 - results.heuristicScore],
        backgroundColor: [
          'rgba(255, 99, 132, 0.8)',
          'rgba(75, 192, 192, 0.8)',
        ],
        borderColor: [
          'rgba(255, 99, 132, 1)',
          'rgba(75, 192, 192, 1)',
        ],
        borderWidth: 1,
      },
    ],
  };

  const isRisky = results.heuristicScore > 5;

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-4">Analysis Results</h2>
      <div className="w-64 h-64 mx-auto mb-6">
        <Pie data={data} />
      </div>
      <div className="space-y-4">
        <div className={`p-4 rounded-lg ${isRisky ? 'bg-red-100' : 'bg-green-100'}`}>
          <h3 className="font-bold text-lg mb-2">
            {isRisky ? 'High Risk Detected' : 'Low Risk File'}
          </h3>
          <p className="text-sm">
            Risk Score: {results.heuristicScore}/10
          </p>
        </div>
        <div className="space-y-4">
          <div>
            <p className="text-sm">
              <span className="font-semibold">File Hash:</span> {results.fileHash}
            </p>
          </div>

          <div>
            <p className="text-sm">
              <span className="font-semibold">File Name:</span> {results.fileName}
            </p>
          </div>

          <div>
            <p className="text-sm">
              <span className="font-semibold">File Size:</span> {(results.fileSize / 1024).toFixed(2)} KB
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}