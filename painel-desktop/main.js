const { app, BrowserWindow, Notification, Tray, Menu } = require('electron');
const path = require('path');
const Store = require('electron-store');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
require('dotenv').config();

let win;
let tray;
const store = new Store();
const PANEL_URL = process.env.PANEL_URL || 'http://localhost:5000/painel';
const POLL_MS = (Number(process.env.POLL_SECONDS) || 30) * 1000;

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 800,
    autoHideMenuBar: true,
    webPreferences: { contextIsolation: true }
  });
  win.loadURL(PANEL_URL);
  win.on('close', (e) => { e.preventDefault(); win.hide(); });
}

async function alertNewCall(qtdNovos) {
  new Notification({ title: 'Novo chamado', body: `Você tem ${qtdNovos} novo(s) chamado(s).` }).show();
  const popup = new BrowserWindow({
    width: 420, height: 180, frame: false, alwaysOnTop: true, skipTaskbar: true
  });
  const html = `
  <html><body style="margin:0;font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100%;background:#111;color:#fff">
    <div style="text-align:center">
      <h2 style="margin:0 0 10px">Novo chamado 📣</h2>
      <p style="margin:0 0 14px">Você tem ${qtdNovos} novo(s) chamado(s).</p>
      <button style="padding:10px 14px;border:none;border-radius:8px;cursor:pointer" onclick="window.close()">OK</button>
    </div>
  </body></html>`;
  popup.loadURL('data:text/html;charset=utf-8,' + encodeURIComponent(html));
  setTimeout(() => { if (!popup.isDestroyed()) popup.close(); }, 8000);
}

async function pollNewCards() {
  try {
    const url = `${PANEL_URL.replace('/painel','')}/api/chamados`;
    const res = await fetch(url);
    const data = await res.json();
    const lastCount = store.get('last_total') || 0;
    const total = data?.total || 0;
    if (total > lastCount) {
      const diff = total - lastCount;
      await alertNewCall(diff);
    }
    store.set('last_total', total);
  } catch (e) {}
}

function createTray() {
  tray = new Tray(path.join(__dirname, 'icon.ico'));
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Abrir painel', click: () => { win.show(); win.focus(); } },
    { label: 'Sair', click: () => { app.quit(); } }
  ]);
  tray.setToolTip('Painel de Chamados');
  tray.setContextMenu(contextMenu);
  tray.on('double-click', () => { win.show(); });
}

app.whenReady().then(() => {
  createWindow();
  createTray();
  setInterval(pollNewCards, POLL_MS);
});
app.on('window-all-closed', (e) => { e.preventDefault(); });
