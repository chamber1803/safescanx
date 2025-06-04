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
    behavioralAnalysis: {
      malicious: boolean;
      details: {
        suspiciousProcesses: string[];
        networkConnections: string[];
        fileOperations: string[];
        registryOperations: string[];
      };
    };
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

  const isRisky = results.heuristicScore > 5 || results.behavioralAnalysis.malicious;

  return (
    <div className="bg-white p-6 rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-4">Analysis Results</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <div className="w-64 h-64 mx-auto mb-6">
            <Pie data={data} />
          </div>
          
          <div className={`p-4 rounded-lg ${isRisky ? 'bg-red-100' : 'bg-green-100'} mb-4`}>
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

        <div className="space-y-4">
          <h3 className="text-xl font-semibold mb-4">Behavioral Analysis</h3>
          
          {results.behavioralAnalysis.details.suspiciousProcesses.length > 0 && (
            <div className="bg-red-50 p-4 rounded-lg">
              <h4 className="font-semibold mb-2">Suspicious Processes</h4>
              <ul className="list-disc list-inside text-sm">
                {results.behavioralAnalysis.details.suspiciousProcesses.map((process, index) => (
                  <li key={index}>{process}</li>
                ))}
              </ul>
            </div>
          )}

          {results.behavioralAnalysis.details.networkConnections.length > 0 && (
            <div className="bg-yellow-50 p-4 rounded-lg">
              <h4 className="font-semibold mb-2">Suspicious Network Connections</h4>
              <ul className="list-disc list-inside text-sm">
                {results.behavioralAnalysis.details.networkConnections.map((connection, index) => (
                  <li key={index}>{connection}</li>
                ))}
              </ul>
            </div>
          )}

          {results.behavioralAnalysis.details.fileOperations.length > 0 && (
            <div className="bg-orange-50 p-4 rounded-lg">
              <h4 className="font-semibold mb-2">Suspicious File Operations</h4>
              <ul className="list-disc list-inside text-sm">
                {results.behavioralAnalysis.details.fileOperations.map((operation, index) => (
                  <li key={index}>{operation}</li>
                ))}
              </ul>
            </div>
          )}

          {results.behavioralAnalysis.details.registryOperations.length > 0 && (
            <div className="bg-purple-50 p-4 rounded-lg">
              <h4 className="font-semibold mb-2">Suspicious Registry Operations</h4>
              <ul className="list-disc list-inside text-sm">
                {results.behavioralAnalysis.details.registryOperations.map((operation, index) => (
                  <li key={index}>{operation}</li>
                ))}
              </ul>
            </div>
          )}

          {Object.values(results.behavioralAnalysis.details).every(arr => arr.length === 0) && (
            <div className="bg-green-50 p-4 rounded-lg">
              <p className="text-sm">No suspicious behavioral patterns detected.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}