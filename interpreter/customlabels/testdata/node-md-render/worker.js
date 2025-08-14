const { parentPort, workerData } = require('worker_threads');
const fs = require('fs/promises');
const cl = require('@polarsignals/custom-labels');

let marked;
(async () => {
  const markedModule = await import('marked');
  marked = markedModule.marked;
})();

const workerId = workerData.workerId;

function mysleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function myrand(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

parentPort.on('message', async ({ filePath, requestId, randomLabels }) => {
  try {
    await cl.withLabels(async () => {
      let data;
      try {
        data = await fs.readFile(filePath);
      } catch (error) {
        if (error.code === 'ENOENT') {
          parentPort.postMessage({
            requestId,
            success: false,
            error: 'File not found'
          });
          return;
        }
        throw error;
      }
      
      const dur = myrand(0, 1000);
      await cl.withLabels(() => mysleep(dur), "sleepDur", "" + dur);

      const md = filePath.endsWith(".md");
      
      let content;
      if (md) {
          content = marked.parse(data.toString());
      } else {
          content = data.toString();
      }

      const htmlResponse = `
        <html>
          <head><title>${filePath}</title></head>
          <body>
${content}
          </body>
        </html>
      `;

      parentPort.postMessage({
        requestId,
        success: true,
        html: htmlResponse
      });
    }, "workerId", `${workerId}`, "filePath", filePath, ...Object.entries(randomLabels || {}).flat());
  } catch (error) {
    parentPort.postMessage({
      requestId,
      success: false,
      error: error.message
    });
  }
});
