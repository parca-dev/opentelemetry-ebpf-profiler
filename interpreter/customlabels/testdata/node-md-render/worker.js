const { parentPort, workerData } = require('worker_threads');
const fs = require('fs/promises');
const marked = require('marked');
const cl = require('@polarsignals/custom-labels');

const workerId = workerData.workerId;

function mysleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function myrand(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

parentPort.on('message', async ({ filePath, requestId }) => {
  try {
    await cl.withLabels(async () => {
      const data = await fs.readFile(filePath);
      
      const dur = myrand(0, 1000);
      await cl.withLabels(() => mysleep(dur), "sleepDur", "" + dur);

      let contents = [];
      const md = filePath.endsWith(".md");
      const n = 1;
      
      for (let i = 0; i < n; ++i) {
        cl.withLabels(() => {
          let content;
          if (md) {
            content = marked.parse(data.toString());
          } else {
            content = data.toString();
          }
          contents[i] = content;
        }, "i", `${i}`);
      }

      const htmlResponse = `
        <html>
          <head><title>${filePath}</title></head>
          <body>
${contents[Math.floor(Math.random() * n)]}
          </body>
        </html>
      `;

      parentPort.postMessage({
        requestId,
        success: true,
        html: htmlResponse
      });
    }, "workerId", `${workerId}`, "filePath", filePath);
  } catch (error) {
    parentPort.postMessage({
      requestId,
      success: false,
      error: error.message
    });
  }
});
