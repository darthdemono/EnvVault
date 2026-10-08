import qrcode from 'qrcode-generator';
import { raw, setHtml } from './html';

/** An inline SVG for `text`. Throws when it does not fit (QR tops out near 2.9 KB). */
export function qrSvg(text: string): string {
  const qr = qrcode(0, 'M'); // type 0: smallest version that fits
  qr.addData(text);
  qr.make();
  return qr.createSvgTag({ cellSize: 6, margin: 2, scalable: true });
}

/** Shows `uri` as a QR code in the overlay. The SVG comes from the encoder and
 * contains only generated geometry, never any of the input text. */
export function showWifiQr(uri: string, ssid: string): void {
  const overlay = document.getElementById('wifi-qr-overlay');
  const body = document.getElementById('wifi-qr-body');
  if (!overlay || !body) return;
  setHtml(body, raw(qrSvg(uri))); // vetted: generated geometry only, see above
  const svg = body.querySelector('svg');
  svg?.setAttribute('role', 'img');
  svg?.setAttribute('aria-label', `QR code to join the Wi-Fi network ${ssid}`);
  overlay.classList.add('open');
}

/** Clears the code from the document when the overlay closes: a passphrase
 * should not sit in the DOM of a screen nobody is looking at. */
export function hideWifiQr(): void {
  document.getElementById('wifi-qr-overlay')?.classList.remove('open');
  const body = document.getElementById('wifi-qr-body');
  if (body) setHtml(body, '');
}
