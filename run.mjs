#!/usr/bin/env node
import 'dotenv/config';
import axios from 'axios';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { SocksProxyAgent } from 'socks-proxy-agent';
import { ethers } from 'ethers';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const {
  DOMAIN = 'community.nitrograph.com',
  ORIGIN = 'https://community.nitrograph.com',
  URI = 'https://community.nitrograph.com',
  CHAIN_ID = '200024',
  NONCE_URL = 'https://api-web.nitrograph.com/api/auth/nonce',
  VERIFY_URL = 'https://api-web.nitrograph.com/api/auth/verify',
  PROFILE_URL = 'https://api-web.nitrograph.com/api/me', // boleh 404
  REFERRAL_CODE = process.env.REFERRAL_CODE || 'ELLM9319',
  REFERRAL_URL_COMM = 'https://community.nitrograph.com/api/referrals/verify',
  MINT_AGENT_URL = 'https://api-web.nitrograph.com/api/credits/mint-agent',
  DAILY_CLAIM_URL = 'https://api-web.nitrograph.com/api/credits/claim',
  DO_REFERRAL = process.env.DO_REFERRAL ?? '1',
  DO_MINT = process.env.DO_MINT ?? '1',
  DO_DAILY = process.env.DO_DAILY ?? '1',
  DO_MISSIONS = process.env.DO_MISSIONS ?? '0', // placeholder
  PRIVATE_KEYS_FILE = process.env.PRIVATE_KEYS_FILE || './privatekeys.txt',
  PROXY_FILE = process.env.PROXY_FILE || './proxy.txt',
  PROXY_URLS = process.env.PROXY_URLS || '', // comma-separated
  DEBUG = process.env.DEBUG ?? '1',
  SAVE_COOKIE = process.env.SAVE_COOKIE ?? '1',
  SESSION_DIR = process.env.SESSION_DIR || path.join(process.cwd(), 'sessions'),
  RPC_URL,
} = process.env;

const isDebug = DEBUG === '1';
const nowIso = () => new Date().toISOString();
const redact = (str, keep = 12) => !str ? str : (String(str).length <= keep ? String(str) : String(str).slice(0, keep) + '…');
const pick = (obj, keys) => { const o = {}; for (const k of keys) if (obj?.[k] !== undefined) o[k] = obj[k]; return o; };
const sleep = (ms) => new Promise(r => setTimeout(r, ms));


function readLines(file) {
  try {
    const s = fs.readFileSync(file, 'utf8');
    return s.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
  } catch {
    return [];
  }
}
function ensureDir(dir) { try { fs.mkdirSync(dir, { recursive: true }); } catch {} }

const allPrivateKeys = (() => {
  let arr = readLines(PRIVATE_KEYS_FILE);
  // also allow env PRIVATE_KEY single run
  if (!arr.length && process.env.PRIVATE_KEY) arr = [process.env.PRIVATE_KEY];
  if (!arr.length) {
    console.error(`❌ Tidak ada private key. Isi ${PRIVATE_KEYS_FILE} (1 per baris) atau set PRIVATE_KEY.`);
    process.exit(1);
  }
  return arr;
})();

const proxyPool = (() => {
  const fileList = readLines(PROXY_FILE);
  const envList = PROXY_URLS.split(',').map(s => s.trim()).filter(Boolean);
  const merged = [...fileList, ...envList];
  return merged;
})();
let proxyIdx = -1;
function nextProxy() {
  if (!proxyPool.length) return null;
  proxyIdx = (proxyIdx + 1) % proxyPool.length;
  return proxyPool[proxyIdx];
}

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
function makeSentryHeaders() {
  const traceId = crypto.randomBytes(16).toString('hex');
  return {
    'sentry-trace': `${traceId}-${traceId.slice(0, 16)}-1`,
    'baggage': [
      'sentry-environment=vercel-production',
      'sentry-sampled=true',
      'sentry-transaction=GET%20%2F',
      'sentry-public_key=3d0b59e37530d1aec91fb2b5bb195a37',
      'sentry-org_id=4509590898081792'
    ].join(',')
  };
}
function buildAxios(proxyUrl) {
  const base = axios.create({
    headers: {
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-GB,en;q=0.8',
      'Origin': ORIGIN,
      'Referer': ORIGIN + '/',
      'User-Agent': UA,
      'Cache-Control': 'no-cache',
      ...makeSentryHeaders(),
    },
  });

  if (proxyUrl) {
    const isSocks = proxyUrl.startsWith('socks5://') || proxyUrl.startsWith('socks4://');
    const agent = isSocks ? new SocksProxyAgent(proxyUrl) : new HttpsProxyAgent(proxyUrl);
    base.defaults.httpAgent = agent;
    base.defaults.httpsAgent = agent;
    base.defaults.proxy = false; // penting untuk axios + *proxy-agent*
  }
  return base;
}


const WAGMI_CONNECTOR_ID = 'io.rabby';
const WAGMI_UID = '4fc3c759580';
function makeWagmiCookies(addr, chainIdNum) {
  const recent = `wagmi.recentConnectorId="${WAGMI_CONNECTOR_ID}"`;
  const storeObj = {
    state: {
      connections: { __type: 'Map', value: [[WAGMI_UID, { accounts: [addr], chainId: chainIdNum, connector: { id: WAGMI_CONNECTOR_ID, name: 'Rabby Wallet', type: 'injected', uid: WAGMI_UID } }]] },
      chainId: chainIdNum,
      current: WAGMI_UID,
    },
    version: 2
  };
  const store = `wagmi.store=${encodeURIComponent(JSON.stringify(storeObj))}`;
  return `${recent}; ${store}`;
}
function bakeCookieJar(...cookieArrays) {
  const parts = [];
  for (const arr of cookieArrays) {
    if (!arr) continue;
    for (const c of arr) {
      const kv = String(c).split(';')[0];
      if (kv && !parts.includes(kv)) parts.push(kv);
    }
  }
  return parts.join('; ');
}
function tryMakeSessionCookiesFromBody(body, address, chainId) {
  const token = body?.token || body?.jwt || body?.accessToken || body?.data?.token;
  if (!token) return [];
  const v1 = `__nitrograph-session-v1=${token}`;
  const v5Obj = {
    token,
    userId: body?.tokenData?.userId || body?.userId || body?.data?.userId,
    snagUserId: body?.tokenData?.snagUserId || body?.snagUserId || body?.data?.snagUserId,
    address,
    chainId,
    expiresAt: body?.expiresAt || (Date.now() + 7 * 86400_000),
    newAccount: !!(body?.tokenData?.newAccount ?? body?.newAccount),
    refreshToken: body?.refreshToken || body?.data?.refreshToken || '',
  };
  const v5 = `@nitrograph/session-v5=${encodeURIComponent(JSON.stringify(v5Obj))}`;
  return [v1, v5];
}
function saveCookieForAddress(addr, cookieJar) {
  if (SAVE_COOKIE !== '1') return null;
  ensureDir(SESSION_DIR);
  const file = path.join(SESSION_DIR, `nitrograph-${addr.toLowerCase()}.cookie`);
  fs.writeFileSync(file, cookieJar);
  return file;
}
function deleteCookieForAddress(addr) {
  const file = path.join(SESSION_DIR, `nitrograph-${addr.toLowerCase()}.cookie`);
  try { fs.unlinkSync(file); } catch {}
}

function buildSiweMessage({ domain, address, statement, uri, chainId, nonce, issuedAt }) {
  return `${domain} wants you to sign in with your Ethereum account:
${address}

${statement}

URI: ${uri}
Version: 1
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}`;
}
async function getNonce(http) {
  const res = await http.get(NONCE_URL, {
    withCredentials: true,
    validateStatus: s => s >= 200 && s < 600,
  });
  if (res.status !== 200) throw new Error(`Nonce request failed: ${res.status}`);
  const nonce = res.data?.nonce || res.data?.data?.nonce || res.data?.result?.nonce;
  if (!nonce) throw new Error('Nonce tidak ditemukan di response.');
  return { nonce, cookies: res.headers['set-cookie'] || [] };
}
async function postVerify(http, payload, cookies) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookies?.length) headers['Cookie'] = cookies.join('; ');
  return http.post(VERIFY_URL, payload, {
    headers, withCredentials: true, validateStatus: s => s >= 200 && s < 600,
  });
}
function validateVerifyAgainstAddress(verifyData, address, chainId) {
  const bodyAddr = verifyData?.tokenData?.walletAddress || verifyData?.address;
  const bodyChain = verifyData?.tokenData?.chainId;
  if (!bodyAddr) throw new Error('Verify OK tapi walletAddress tidak ada di body.');
  if (bodyAddr.toLowerCase() !== address.toLowerCase()) {
    throw new Error(`Verify untuk alamat lain! expected=${address} got=${bodyAddr}`);
  }
  if (bodyChain && Number(bodyChain) !== Number(chainId)) {
    throw new Error(`ChainId mismatch! expected=${chainId} got=${bodyChain}`);
  }
}

async function referralOnceCommunity(http, cookieJar, referralCode, addr, chainId) {
  if (!referralCode) { console.log('↷ Referral skipped (empty code).'); return; }
  try {
    const headers = {
      'Content-Type': 'application/json',
      'Referer': ORIGIN + '/app/missions',
      'Cookie': [cookieJar, makeWagmiCookies(addr, chainId)].filter(Boolean).join('; ')
    };
    const res = await http.post(REFERRAL_URL_COMM, { referralCode }, {
      headers, withCredentials: true, validateStatus: s => s >= 200 && s < 600,
    });
    if (res.status === 200) {
      const msg = res.data?.message || res.data?.status || 'OK';
      console.log(`✅ Referral submitted: ${msg}`);
    } else if (res.status === 409) {
      console.log('ℹ️ Referral already set (409).');
    } else if (res.status === 400) {
      console.log('⚠️ Referral code invalid (400).');
    } else {
      console.log('ℹ️ Look Good.');
    }
  } catch {
    console.log('ℹ️ Look Good).');
  }
}

async function mintAgent(http, token, cookieJar) {
  const headers = { 'Authorization': `Bearer ${token}`, 'Cookie': cookieJar || '' };
  const res = await http.post(MINT_AGENT_URL, {}, {
    headers, withCredentials: true, validateStatus: s => s >= 200 && s < 600,
  });
  if (res.status < 300 && res.data?.success) {
    console.log(`✅ Mint agent: success | tokenId=${res.data?.tokenId} | tx=${res.data?.transactionHash}`);
  } else if (res.status === 400) {
    console.log('ℹ️ Mint agent: already minted (400).');
  } else {
    console.log(`⚠️ Mint agent status=${res.status}`);
  }
}

async function claimDaily(http, token, cookieJar) {
  const headers = { 'Authorization': `Bearer ${token}`, 'Cookie': cookieJar || '' };
  const res = await http.post(DAILY_CLAIM_URL, {}, {
    headers, withCredentials: true, validateStatus: s => s >= 200 && s < 600,
  });
  if (res.status < 300 && res.data?.success) {
    console.log(`✅ Daily claimed: +${res.data?.claimedAmount} → ${res.data?.newBalance}`);
  } else if (res.status === 409 || res.status === 400) {
    console.log('ℹ️ Daily already claimed today.');
  } else {
    console.log(`⚠️ Daily claim status=${res.status}`);
  }
}

// Placeholder missions
async function claimAllClaimableMissions(/* http, token */) {
  console.log('↷ Missions claim skipped (endpoint tidak disediakan).');
}

ensureDir(SESSION_DIR);

let currentAddressForCleanup = null;
let scheduledCleanup = false;
function cleanupSessionIfAny() {
  if (currentAddressForCleanup) {
    deleteCookieForAddress(currentAddressForCleanup);
    currentAddressForCleanup = null;
  }
}
function setupExitHandlersOnce() {
  if (scheduledCleanup) return;
  scheduledCleanup = true;
  for (const sig of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
    process.on(sig, () => { cleanupSessionIfAny(); process.exit(0); });
  }
  process.on('exit', () => { cleanupSessionIfAny(); });
}
setupExitHandlersOnce();

const CHAIN_ID_NUM = Number(CHAIN_ID) || 200024;

async function runForPrivateKey(pkRaw, idx) {
  // rotate proxy per account
  const proxy = nextProxy();
  const http = buildAxios(proxy);

  const pk = pkRaw.startsWith('0x') ? pkRaw : ('0x' + pkRaw);
  const provider = RPC_URL ? new ethers.JsonRpcProvider(RPC_URL) : undefined;
  const wallet = new ethers.Wallet(pk, provider);
  const address = await wallet.getAddress();

  currentAddressForCleanup = address; // mark for cleanup on exit

  console.log(`\n== [${idx+1}/${allPrivateKeys.length}] Nitrograph: Login → Referral → Mint → Daily (proxy: ${proxy ? redact(proxy, 24) : 'none'}) ==`);
  console.log('address:', address);
  console.log('chainId:', CHAIN_ID_NUM);

  // SIWE
  const { nonce, cookies: nonceCookies } = await getNonce(http);
  const message = buildSiweMessage({
    domain: DOMAIN,
    address,
    statement: 'Sign in to Nitrograph using your wallet',
    uri: URI,
    chainId: CHAIN_ID_NUM,
    nonce,
    issuedAt: nowIso(),
  });
  const signature = await wallet.signMessage(message);

  let verifyRes = await postVerify(http, { message, signature }, nonceCookies);
  if (verifyRes.status >= 400) {
    verifyRes = await postVerify(http, { address, message, signature }, nonceCookies);
  }
  if (verifyRes.status >= 400) throw new Error(`Verify gagal: ${verifyRes.status}`);

  validateVerifyAgainstAddress(verifyRes.data, address, CHAIN_ID_NUM);

  // session cookie & token
  let sessionCookies = verifyRes.headers['set-cookie'] || [];
  if (sessionCookies.length === 0) sessionCookies = tryMakeSessionCookiesFromBody(verifyRes.data, address, CHAIN_ID_NUM);
  const cookieJar = bakeCookieJar(sessionCookies);
  const token = verifyRes.data?.token;
  if (!cookieJar && !token) throw new Error('Tidak ada session cookie/token setelah verify.');

  if (cookieJar && SAVE_COOKIE === '1') {
    const saved = saveCookieForAddress(address, cookieJar);
    if (saved && isDebug) console.log('cookie saved →', saved);
  }

  // Referral (single-shot)
  if (DO_REFERRAL === '1' && REFERRAL_CODE) {
    await referralOnceCommunity(http, cookieJar, (REFERRAL_CODE || '').trim(), address, CHAIN_ID_NUM);
  } else {
    console.log('↷ Referral skipped.');
  }

  // Mint agent
  if (DO_MINT === '1') {
    await mintAgent(http, token, cookieJar);
  } else {
    console.log('↷ Mint agent skipped.');
  }

  // Daily claim
  if (DO_DAILY === '1') {
    await claimDaily(http, token, cookieJar);
  } else {
    console.log('↷ Daily claim skipped.');
  }

  // Missions (placeholder)
  if (DO_MISSIONS === '1') {
    await claimAllClaimableMissions(/* http, token */);
  }

  // cleanup session file after account done
  cleanupSessionIfAny();

  // small delay between accounts to be gentle
  await sleep(500);
}

(async () => {
  for (let i = 0; i < allPrivateKeys.length; i++) {
    try {
      await runForPrivateKey(allPrivateKeys[i], i);
    } catch (e) {
      console.error(`\n❌ Akun #${i+1} gagal:`, e?.message);
      if (e?.response) {
        console.error('HTTP', e.response.status, e.response.statusText);
        console.error('Body keys:', e.response?.data && typeof e.response.data === 'object' ? Object.keys(e.response.data) : typeof e.response.data);
        if (isDebug) console.error('Headers:', pick(e.response.headers, ['content-type']));
      }
      // pastikan session dibersihkan walau error
      cleanupSessionIfAny();
    }
  }
  process.exit(0);
})();
