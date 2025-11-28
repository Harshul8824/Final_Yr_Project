#!/usr/bin/env node

/**
 * Test script for WHOIS endpoint
 * Run with: node test_whois.js
 */

const axios = require('axios');

const BASE_URL = 'http://localhost:5000';
const ENDPOINT = '/api/whois/getrecord';

// Test cases
const testCases = [
    {
        name: 'Valid Domain',
        data: { host: 'google.com' },
        expectedStatus: 200
    },
    {
        name: 'Valid IP',
        data: { host: '8.8.8.8' },
        expectedStatus: 200
    },
    {
        name: 'XSS Attack',
        data: { host: '<script>alert("xss")</script>' },
        expectedStatus: 400
    },
    {
        name: 'JavaScript Injection',
        data: { host: 'javascript:alert("hack")' },
        expectedStatus: 400
    },
    {
        name: 'Invalid Format',
        data: { host: 'invalid..hostname..test' },
        expectedStatus: 400
    },
    {
        name: 'Empty Body',
        data: {},
        expectedStatus: 400
    },
    {
        name: 'Very Long Input',
        data: { host: 'verylonghostnamethatexceedsthemaximumlengthallowedforadomainnameandshouldberejectedbytheserverbecauseitistoolongandinvalid' },
        expectedStatus: 400
    },
    {
        name: 'Non-existent Domain',
        data: { host: 'thisdomaindoesnotexist12345.com' },
        expectedStatus: 404
    }
];

async function runTest(testCase) {
    try {
        console.log(`\n🧪 Testing: ${testCase.name}`);
        console.log(`📤 Input: ${JSON.stringify(testCase.data)}`);
        
        const startTime = Date.now();
        const response = await axios.post(`${BASE_URL}${ENDPOINT}`, testCase.data, {
            timeout: 35000, // 35 seconds timeout
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const endTime = Date.now();
        
        console.log(`✅ Status: ${response.status}`);
        console.log(`⏱️  Time: ${endTime - startTime}ms`);
        console.log(`📥 Response: ${JSON.stringify(response.data, null, 2)}`);
        
        if (response.status === testCase.expectedStatus) {
            console.log(`✅ PASS: Expected status ${testCase.expectedStatus}`);
        } else {
            console.log(`❌ FAIL: Expected status ${testCase.expectedStatus}, got ${response.status}`);
        }
        
    } catch (error) {
        const endTime = Date.now();
        console.log(`❌ Error: ${error.message}`);
        
        if (error.response) {
            console.log(`📥 Status: ${error.response.status}`);
            console.log(`📥 Response: ${JSON.stringify(error.response.data, null, 2)}`);
            
            if (error.response.status === testCase.expectedStatus) {
                console.log(`✅ PASS: Expected status ${testCase.expectedStatus}`);
            } else {
                console.log(`❌ FAIL: Expected status ${testCase.expectedStatus}, got ${error.response.status}`);
            }
        } else {
            console.log(`❌ FAIL: Network error or timeout`);
        }
    }
}

async function runAllTests() {
    console.log('🚀 Starting WHOIS Endpoint Tests...');
    console.log(`📍 Testing against: ${BASE_URL}${ENDPOINT}`);
    
    for (const testCase of testCases) {
        await runTest(testCase);
        // Wait 1 second between tests
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log('\n🏁 All tests completed!');
}

// Check if server is running
async function checkServer() {
    try {
        await axios.get(`${BASE_URL}/api/analytics/getallanalytics`, { timeout: 5000 });
        console.log('✅ Server is running');
        return true;
    } catch (error) {
        console.log('❌ Server is not running or not accessible');
        console.log('Please start the server with: npm start');
        return false;
    }
}

// Main execution
async function main() {
    const serverRunning = await checkServer();
    if (serverRunning) {
        await runAllTests();
    }
}

main().catch(console.error);

