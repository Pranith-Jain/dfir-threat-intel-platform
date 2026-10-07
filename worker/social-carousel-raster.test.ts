import { describe, it, expect, vi } from 'vitest';
import { readFileSync } from 'node:fs';

// Vitest (Node) cannot import *.wasm as an ESM module the way Wrangler/Miniflare
// can at bundle time.  Mock the import so the shared init still runs, but via a
// WebAssembly.Module built from the real bytes — giving us an actual rasterisation
// smoke test rather than a stub.
vi.mock('@resvg/resvg-wasm/index_bg.wasm', () => {
  const bytes = readFileSync('node_modules/@resvg/resvg-wasm/index_bg.wasm');
  // Workers types declare WebAssembly.Module as abstract (compiled at build time),
  // but in Node.js vitest we can construct one from the raw bytes.

  return { default: new (WebAssembly.Module as any)(bytes) as WebAssembly.Module };
});

// Was ./social-carousel-raster — a byte-identical duplicate nothing imported.
import { carouselSlideToPng } from '../api/src/lib/social-carousel-raster';

// Minimal Env stub: ASSETS.fetch returns the real font bytes from disk.
const env = {
  ASSETS: {
    fetch: async (req: Request) => {
      const path = new URL(req.url).pathname; // e.g. /og/hanken-400.ttf
      const bytes = readFileSync(`public${path}`);
      return new Response(bytes);
    },
  },
} as unknown as Parameters<typeof carouselSlideToPng>[0];

describe('carouselSlideToPng', () => {
  it('rasterizes an SVG to PNG (magic bytes)', async () => {
    const svg =
      '<svg xmlns="http://www.w3.org/2000/svg" width="1080" height="1350"><rect width="1080" height="1350" fill="#fff"/><text x="80" y="200" font-family="Hanken Grotesk" font-size="48">hi</text></svg>';
    const png = await carouselSlideToPng(env, svg);
    expect(png[0]).toBe(0x89);
    expect(png[1]).toBe(0x50); // P
    expect(png[2]).toBe(0x4e); // N
    expect(png[3]).toBe(0x47); // G
  });
});
