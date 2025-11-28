import React from 'react';

const DebugInfo = ({ result, methodName }) => {
  if (!result) return null;

  return (
    <div className="mt-4 p-3 bg-gray-50 rounded-md">
      <h4 className="text-sm font-medium text-gray-700 mb-2">Debug Info for {methodName}:</h4>
      <pre className="text-xs text-gray-600 overflow-x-auto">
        {JSON.stringify(result, null, 2)}
      </pre>
    </div>
  );
};

export default DebugInfo;

