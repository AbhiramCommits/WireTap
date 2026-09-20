// Captures a screenshot of the live dashboard for docs/.
// Run with the stack up: feedgen -> wiretap_recv (--dash-socket) -> backend.
//   node tools/dashboard/screenshot.mjs [url] [out.png] [wait_ms]
import { chromium } from "playwright";

const url = process.argv[2] ?? "http://localhost:8011";
const out = process.argv[3] ?? "docs/dashboard.png";
const waitMs = Number(process.argv[4] ?? 20000);

const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
await page.goto(url, { waitUntil: "networkidle" });
await page.waitForTimeout(waitMs); // let live data + histogram accumulate
await page.screenshot({ path: out });
console.log(`screenshot written to ${out}`);
await browser.close();
