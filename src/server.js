'use strict';

const express = require('express');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { spawn } = require('child_process');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_FILE_MB = Number(process.env.MAX_FILE_MB || 500);
const MAX_FILE_BYTES = MAX_FILE_MB * 1024 * 1024;
const JOB_TTL_MINUTES = Number(process.env.JOB_TTL_MINUTES || 60);
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || '').replace(/\/$/, '');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || 'https://www.soft3tt.online,https://soft3tt.online')
  .split(',').map(s => s.trim()).filter(Boolean);
const STORAGE = path.resolve(process.env.STORAGE_DIR || path.join(process.cwd(), 'storage', 'jobs'));

// Debian's ImageMagick package commonly exposes the ImageMagick 6 CLI as `convert`
// rather than the ImageMagick 7 `magick` launcher. Allow an environment override
// and default to `convert` for Render's Debian-based Docker image.
const IMAGE_TOOL = process.env.IMAGEMAGICK_BIN || 'convert';

const TOOL_DEFS = {
  'mov-to-mp4': { ext: 'mp4', mime: 'video/mp4', kind: 'video' },
  'mp4-to-webm': { ext: 'webm', mime: 'video/webm', kind: 'video' },
  'video-to-mp3': { ext: 'mp3', mime: 'audio/mpeg', kind: 'audio' },
  'mp4-to-mp3': { ext: 'mp3', mime: 'audio/mpeg', kind: 'audio' },
  'wav-to-mp3': { ext: 'mp3', mime: 'audio/mpeg', kind: 'audio' },
  'm4a-to-mp3': { ext: 'mp3', mime: 'audio/mpeg', kind: 'audio' },
  'video-to-gif': { ext: 'gif', mime: 'image/gif', kind: 'video' },
  'jpg-to-png': { ext: 'png', mime: 'image/png', kind: 'image' },
  'png-to-jpg': { ext: 'jpg', mime: 'image/jpeg', kind: 'image' },
  'webp-to-jpg': { ext: 'jpg', mime: 'image/jpeg', kind: 'image' },
  'heic-to-jpg': { ext: 'jpg', mime: 'image/jpeg', kind: 'image' },
  'jpg-to-pdf': { ext: 'pdf', mime: 'application/pdf', kind: 'image' },
  'pdf-to-jpg': { ext: 'jpg', mime: 'image/jpeg', kind: 'pdf' },
  'pdf-to-word': { ext: 'docx', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', kind: 'document' },
  'word-to-pdf': { ext: 'pdf', mime: 'application/pdf', kind: 'document' }
};

const upload = multer({
  storage: multer.diskStorage({
    destination: async (req, file, cb) => {
      try { await fsp.mkdir(STORAGE, { recursive: true }); cb(null, STORAGE); }
      catch (e) { cb(e); }
    },
    filename: (req, file, cb) => cb(null, `${crypto.randomUUID()}-input`)
  }),
  limits: { fileSize: MAX_FILE_BYTES, files: 1, fields: 10, parts: 12 },
  fileFilter: (req, file, cb) => cb(null, true)
});

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('Origin not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept'],
  exposedHeaders: ['Content-Disposition']
}));
app.use(express.json({ limit: '64kb' }));

function safeName(name) {
  return String(name).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 120);
}
function jobId() { return crypto.randomUUID(); }
async function exists(p) { try { await fsp.access(p); return true; } catch { return false; } }

function run(cmd, args, { timeoutMs = 10 * 60 * 1000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error(`${cmd} timed out`)); }, timeoutMs);
    child.on('error', e => { clearTimeout(timer); reject(e); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve({ stdout, stderr });
      else reject(new Error(`${cmd} exited with code ${code}: ${stderr.slice(-4000)}`));
    });
  });
}

async function validateInput(file, tool) {
  const lower = String(file.originalname || '').toLowerCase();
  const allowed = {
    'mov-to-mp4': ['.mov'], 'mp4-to-webm': ['.mp4'], 'video-to-mp3': ['.mp4','.mov','.mkv','.webm','.avi','.m4v'],
    'mp4-to-mp3': ['.mp4'], 'wav-to-mp3': ['.wav'], 'm4a-to-mp3': ['.m4a'], 'video-to-gif': ['.mp4','.mov','.mkv','.webm'],
    'jpg-to-png': ['.jpg','.jpeg'], 'png-to-jpg': ['.png'], 'webp-to-jpg': ['.webp'], 'heic-to-jpg': ['.heic','.heif'],
    'jpg-to-pdf': ['.jpg','.jpeg'], 'pdf-to-jpg': ['.pdf'], 'pdf-to-word': ['.pdf'], 'word-to-pdf': ['.doc','.docx']
  };
  const ext = path.extname(lower);
  if (!allowed[tool]?.includes(ext)) throw new Error(`Unsupported input type for ${tool}.`);

  // Basic magic-byte checks for common binary formats. FFmpeg/ImageMagick/LibreOffice
  // still perform their own decoding; the extension is not trusted as a security boundary.
  const fh = await fsp.open(file.path, 'r');
  const buf = Buffer.alloc(16);
  await fh.read(buf, 0, 16, 0); await fh.close();
  const hex = buf.toString('hex');
  if (['jpg-to-png','png-to-jpg','webp-to-jpg','heic-to-jpg','jpg-to-pdf'].includes(tool)) {
    const ok = hex.startsWith('ffd8ff') || hex.startsWith('89504e470d0a1a0a') || hex.startsWith('52494646') || hex.includes('6674797068656963');
    if (!ok) throw new Error('The uploaded file does not appear to be a supported image.');
  }
  if (['pdf-to-jpg','pdf-to-word'].includes(tool) && !buf.toString('ascii',0,5).startsWith('%PDF-')) throw new Error('The uploaded file is not a valid PDF.');
}

async function convertFile(tool, input, output, opts) {
  const quality = opts.quality || 'original';
  const audio = opts.audio || 'original';
  switch (tool) {
    case 'mov-to-mp4': {
      const args = ['-y','-i',input,'-map','0:v:0','-map','0:a?','-c:v','libx264','-preset','veryfast','-pix_fmt','yuv420p'];
      if (quality !== 'original') args.push('-vf', `scale=-2:${Number(quality)}`);
      args.push('-c:a','aac','-b:a', audio === 'original' ? '192k' : `${audio}k`, output);
      return run('ffmpeg', args);
    }
    case 'mp4-to-webm': return run('ffmpeg',['-y','-i',input,'-c:v','libvpx-vp9','-crf','32','-b:v','0','-c:a','libopus','-b:a','128k',output]);
    case 'video-to-mp3':
    case 'mp4-to-mp3': return run('ffmpeg',['-y','-i',input,'-vn','-c:a','libmp3lame','-b:a',audio === 'original' ? '192k' : `${audio}k`,output]);
    case 'wav-to-mp3':
    case 'm4a-to-mp3': return run('ffmpeg',['-y','-i',input,'-c:a','libmp3lame','-b:a',audio === 'original' ? '192k' : `${audio}k`,output]);
    case 'video-to-gif': return run('ffmpeg',['-y','-i',input,'-vf','fps=12,scale=640:-1:flags=lanczos','-t','20',output]);
    case 'jpg-to-png': return run(IMAGE_TOOL,[input,output]);
    case 'png-to-jpg': return run(IMAGE_TOOL,[input,'-background','white','-alpha','remove','-alpha','off','-quality','92',output]);
    case 'webp-to-jpg': return run(IMAGE_TOOL,[input,'-background','white','-alpha','remove','-alpha','off','-quality','92',output]);
    case 'heic-to-jpg': return run(IMAGE_TOOL,[input,'-quality','92',output]);
    case 'jpg-to-pdf': return run(IMAGE_TOOL,[input,'-background','white','-alpha','remove','-alpha','off',output]);
    case 'pdf-to-jpg': return run(IMAGE_TOOL,[`${input}[0]`,'-quality','92',output]);
    case 'word-to-pdf': return run('libreoffice',['--headless','--convert-to','pdf','--outdir',path.dirname(output),input]);
    case 'pdf-to-word': throw new Error('PDF to Word requires a dedicated PDF/OCR conversion pipeline and is not enabled in this first backend release.');
    default: throw new Error('Unsupported conversion tool.');
  }
}

app.get('/api/health', async (req,res) => {
  res.json({ ok:true, service:'Soft3TT Conversion API', version:'1.0.1', configured:true, maxFileMB:MAX_FILE_MB, tools:Object.keys(TOOL_DEFS) });
});
app.get('/api/tools', (req,res) => res.json({ ok:true, tools:TOOL_DEFS }));

app.post('/api/convert', upload.single('file'), async (req,res,next) => {
  let inputPath = req.file?.path;
  let outputPath = null;
  try {
    if (!req.file) return res.status(400).json({ ok:false, message:'No file uploaded. Field name must be "file".' });
    const tool = String(req.body.tool || '').trim();
    if (!TOOL_DEFS[tool]) throw new Error('Unsupported conversion tool.');
    await validateInput(req.file, tool);

    const id = jobId();
    const def = TOOL_DEFS[tool];
    const base = path.join(STORAGE, id);
    await fsp.mkdir(base, { recursive:true });
    const input = path.join(base, `input${path.extname(req.file.originalname).toLowerCase() || '.bin'}`);
    outputPath = path.join(base, `result.${def.ext}`);
    await fsp.rename(inputPath, input); inputPath = input;

    await convertFile(tool, input, outputPath, { quality:req.body.quality, audio:req.body.audio });

    // LibreOffice writes based on its input name. Normalize its generated PDF if needed.
    if (tool === 'word-to-pdf' && !(await exists(outputPath))) {
      const generated = path.join(base, `${path.basename(req.file.originalname, path.extname(req.file.originalname))}.pdf`);
      if (await exists(generated)) await fsp.rename(generated, outputPath);
    }
    if (!(await exists(outputPath))) throw new Error('Conversion completed without producing an output file.');

    await fsp.writeFile(path.join(base,'job.json'), JSON.stringify({id,tool,createdAt:Date.now(),inputName:safeName(req.file.originalname),outputName:`Soft3TT-${tool}.${def.ext}`},null,2));
    const downloadUrl = `${PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`}/api/download/${id}`;
    return res.json({ ok:true, jobId:id, tool, downloadUrl, filename:`Soft3TT-${tool}.${def.ext}`, expiresInMinutes:JOB_TTL_MINUTES });
  } catch (err) {
    if (inputPath) await fsp.rm(inputPath,{force:true}).catch(()=>{});
    if (outputPath) await fsp.rm(outputPath,{force:true}).catch(()=>{});
    return next(err);
  }
});

app.get('/api/download/:id', async (req,res,next) => {
  try {
    if (!/^[a-f0-9-]{36}$/.test(req.params.id)) return res.status(400).json({ok:false,message:'Invalid job id.'});
    const dir = path.join(STORAGE, req.params.id);
    const metaPath = path.join(dir,'job.json');
    const meta = JSON.parse(await fsp.readFile(metaPath,'utf8'));
    if (Date.now() - meta.createdAt > JOB_TTL_MINUTES*60*1000) {
      await fsp.rm(dir,{recursive:true,force:true});
      return res.status(410).json({ok:false,message:'This conversion has expired.'});
    }
    const output = path.join(dir, `result.${TOOL_DEFS[meta.tool].ext}`);
    if (!(await exists(output))) return res.status(404).json({ok:false,message:'Converted file not found.'});
    res.setHeader('Content-Type',TOOL_DEFS[meta.tool].mime);
    res.setHeader('Content-Disposition',`attachment; filename="${meta.outputName}"`);
    return res.sendFile(output);
  } catch (err) { return next(err); }
});

async function cleanupExpired(){
  await fsp.mkdir(STORAGE,{recursive:true});
  const entries = await fsp.readdir(STORAGE,{withFileTypes:true});
  const cutoff = Date.now() - JOB_TTL_MINUTES*60*1000;
  for(const e of entries){
    if(!e.isDirectory()) continue;
    const meta = path.join(STORAGE,e.name,'job.json');
    try { const j=JSON.parse(await fsp.readFile(meta,'utf8')); if(j.createdAt < cutoff) await fsp.rm(path.join(STORAGE,e.name),{recursive:true,force:true}); }
    catch { /* remove orphan temp directories older than TTL based on mtime */
      try { const st=await fsp.stat(path.join(STORAGE,e.name)); if(st.mtimeMs < cutoff) await fsp.rm(path.join(STORAGE,e.name),{recursive:true,force:true}); } catch {}
    }
  }
}
setInterval(()=>cleanupExpired().catch(()=>{}), 10*60*1000);
cleanupExpired().catch(()=>{});

app.use((err,req,res,next) => {
  console.error(err);
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ok:false,message:`File exceeds the ${MAX_FILE_MB} MB limit.`});
    return res.status(400).json({ok:false,message:err.message});
  }
  const status = /Origin not allowed|Unsupported conversion|not valid|Unsupported input|requires a dedicated|No file/.test(err.message||'') ? 400 : 500;
  return res.status(status).json({ok:false,message:err.message || 'Internal conversion error.'});
});

app.listen(PORT,HOST,()=>console.log(`Soft3TT Conversion API listening on ${HOST}:${PORT}`));
