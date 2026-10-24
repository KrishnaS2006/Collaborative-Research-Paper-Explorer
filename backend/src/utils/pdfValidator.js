import { createReadStream } from 'node:fs';

/**
 * Validates that a file is a real PDF by checking its magic bytes.
 * The first 4–5 bytes of any valid PDF file are "%PDF-".
 *
 * @param {string} filePath - Absolute path to the file on disk.
 * @returns {Promise<boolean>} true if valid PDF, false otherwise.
 */
export async function isValidPdf(filePath) {
  return new Promise((resolve) => {
    const stream = createReadStream(filePath, { start: 0, end: 4 });
    const chunks = [];
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => {
      const header = Buffer.concat(chunks).toString('ascii');
      resolve(header.startsWith('%PDF'));
    });
    stream.on('error', () => resolve(false));
  });
}
