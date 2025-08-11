const http = require('http');
const fs = require('fs/promises');
const path = require('path');
const marked = require('marked');
const cl = require('@polarsignals/custom-labels');
const { Worker } = require('worker_threads');

// require('@polarsignals/custom-labels');
// const cl = {
//     withLabel: function(x, y, z) {
//         return z();
//     }
// };

const PORT = 3000;
const WORKER_COUNT = 8;

const begin = Date.now();

function mysleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function myrand(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Worker pool management
const workers = [];
const workerQueue = [];
let currentWorker = 0;
const pendingRequests = new Map();
let requestIdCounter = 0;

// Initialize worker pool
for (let i = 0; i < WORKER_COUNT; i++) {
  const worker = new Worker(path.join(__dirname, 'worker.js'), {
    workerData: { workerId: i }
  });
  
  worker.on('message', ({ requestId, success, html, error }) => {
    const { res } = pendingRequests.get(requestId);
    pendingRequests.delete(requestId);
    
    if (success) {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/html' });
      res.end(`<h1>Error: ${error}</h1>`);
    }
    
    // Return worker to pool
    workerQueue.push(worker);
  });
  
  worker.on('error', (error) => {
    console.error('Worker error:', error);
  });
  
  workerQueue.push(worker);
  workers.push(worker);
}

function processWithWorker(filePath, res) {
  const requestId = ++requestIdCounter;
  pendingRequests.set(requestId, { res });
  
  if (workerQueue.length > 0) {
    const worker = workerQueue.shift();
    worker.postMessage({ filePath, requestId });
  } else {
    // All workers busy, use round-robin
    const worker = workers[currentWorker];
    currentWorker = (currentWorker + 1) % WORKER_COUNT;
    worker.postMessage({ filePath, requestId });
  }
}

const server = http.createServer((req, res) => {
    const filePath = path.join(__dirname, req.url);
    
    cl.withLabels(() => {
        processWithWorker(filePath, res);
    }, "filePath", filePath);
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
