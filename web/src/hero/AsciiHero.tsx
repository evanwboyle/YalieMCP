import { useEffect, useRef } from "react";
import * as THREE from "three";

// Density ramp: index 0 = empty space, last = densest glyph
// Density ramp built entirely from variations of "y"
const GLYPHS = " ʸýÿyYÝŸ¥Ұ";
const CELL_BASE = 11; // CSS px per character cell

const NOISE_GLSL = /* glsl */ `
vec3 mod289(vec3 x){return x - floor(x * (1.0/289.0)) * 289.0;}
vec4 mod289(vec4 x){return x - floor(x * (1.0/289.0)) * 289.0;}
vec4 permute(vec4 x){return mod289(((x*34.0)+1.0)*x);}
vec4 taylorInvSqrt(vec4 r){return 1.79284291400159 - 0.85373472095314 * r;}
float snoise(vec3 v){
  const vec2 C = vec2(1.0/6.0, 1.0/3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + C.xxx;
  vec3 x2 = x0 - i2 + C.yyy;
  vec3 x3 = x0 - D.yyy;
  i = mod289(i);
  vec4 p = permute(permute(permute(i.z + vec4(0.0, i1.z, i2.z, 1.0))
        + i.y + vec4(0.0, i1.y, i2.y, 1.0))
        + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 0.142857142857;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ * ns.x + ns.yyyy;
  vec4 y = y_ * ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0) * 2.0 + 1.0;
  vec4 s1 = floor(b1) * 2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
}
`;

const FRAGMENT = /* glsl */ `
precision highp float;
uniform sampler2D uText;
uniform sampler2D uGlyphs;
uniform vec2 uRes;
uniform vec2 uMouse;
uniform float uTime;
uniform float uCell;
uniform float uGlyphCount;
uniform float uReveal;
${NOISE_GLSL}
void main() {
  vec2 frag = gl_FragCoord.xy;
  vec2 cellId = floor(frag / uCell);
  vec2 center = (cellId + 0.5) * uCell;
  vec2 uv = center / uRes;
  vec2 m = uMouse / uRes;
  float aspect = uRes.x / uRes.y;

  vec2 d = uv - m;
  d.x *= aspect;
  float dist = length(d);

  // Cursor repulsion + ambient wobble distort the sampling coordinates
  vec2 duv = uv;
  duv += (d / max(dist, 1e-4)) * vec2(1.0 / aspect, 1.0) * 0.028 * exp(-dist * dist * 14.0);
  duv.x += 0.005 * snoise(vec3(uv * 2.4, uTime * 0.18));
  duv.y += 0.005 * snoise(vec3(uv * 2.4 + 11.7, uTime * 0.18));

  // Pseudo-3D: extrude the text along a mouse-driven tilt vector
  vec2 tilt = (vec2(0.5) - m) * 0.07;
  float face = texture2D(uText, duv).r;
  float depth = 0.0;
  for (int i = 1; i <= 9; i++) {
    float t = float(i) / 9.0;
    depth = max(depth, texture2D(uText, duv + tilt * t).r * (1.0 - 0.45 * t));
  }
  // Solid bright face, clean mid-density shadow trailing behind it
  float lum = face > 0.35 ? 1.0 : depth * 0.38;

  // Background: drifting noise field + a lantern that follows the cursor
  float field = snoise(vec3(cellId * 0.085, uTime * 0.16));
  float bg = 0.045 + 0.075 * smoothstep(0.15, 1.0, field);
  float l = max(lum, bg) * uReveal;

  // Map luminance to a glyph in the atlas
  float gi = floor(clamp(l, 0.0, 0.999) * uGlyphCount);
  vec2 sub = fract(frag / uCell);
  vec2 guv = vec2((gi + sub.x) / uGlyphCount, sub.y);
  float g = texture2D(uGlyphs, guv).r;

  vec3 cDeep = vec3(0.04, 0.09, 0.24);
  vec3 cBlue = vec3(0.15, 0.34, 0.68);
  vec3 cIce  = vec3(0.80, 0.93, 1.0);
  vec3 col = mix(cDeep, cBlue, smoothstep(0.0, 0.55, l));
  col = mix(col, cIce, smoothstep(0.55, 1.0, l));

  float vig = 1.0 - 0.55 * smoothstep(0.45, 1.05, length(uv - vec2(0.5, 0.52)));
  vec3 base = vec3(0.012, 0.02, 0.04);
  gl_FragColor = vec4(base + col * g * vig, 1.0);
}
`;

const VERTEX = /* glsl */ `
void main() { gl_Position = vec4(position.xy, 0.0, 1.0); }
`;

function drawTextCanvas(canvas: HTMLCanvasElement, w: number, h: number) {
  canvas.width = Math.max(2, Math.floor(w / 2));
  canvas.height = Math.max(2, Math.floor(h / 2));
  const ctx = canvas.getContext("2d")!;
  const cw = canvas.width;
  const ch = canvas.height;
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, cw, ch);
  ctx.fillStyle = "#fff";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  const lines = ["YALIE", "MCP"];
  const fs = Math.min(cw / 3.5, ch * 0.26);
  ctx.font = `700 ${fs}px "IBM Plex Mono", monospace`;
  const gap = fs * 0.92;
  const y0 = ch * 0.335 - gap / 2;
  lines.forEach((line, i) => ctx.fillText(line, cw / 2, y0 + i * gap));
}

function drawGlyphAtlas(canvas: HTMLCanvasElement) {
  const cell = 64;
  canvas.width = cell * GLYPHS.length;
  canvas.height = cell;
  const ctx = canvas.getContext("2d")!;
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = "#fff";
  ctx.textAlign = "center";
  ctx.textBaseline = "middle";
  ctx.font = `700 ${cell * 0.78}px "IBM Plex Mono", monospace`;
  for (let i = 0; i < GLYPHS.length; i++) {
    ctx.fillText(GLYPHS[i], i * cell + cell / 2, cell * 0.54);
  }
}

export default function AsciiHero() {
  const hostRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const renderer = new THREE.WebGLRenderer({ antialias: false, alpha: false });
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    renderer.setPixelRatio(dpr);
    host.appendChild(renderer.domElement);

    const textCanvas = document.createElement("canvas");
    const glyphCanvas = document.createElement("canvas");
    const textTex = new THREE.CanvasTexture(textCanvas);
    textTex.minFilter = THREE.LinearFilter;
    textTex.magFilter = THREE.LinearFilter;
    const glyphTex = new THREE.CanvasTexture(glyphCanvas);
    glyphTex.minFilter = THREE.NearestFilter;
    glyphTex.magFilter = THREE.NearestFilter;

    const uniforms = {
      uText: { value: textTex },
      uGlyphs: { value: glyphTex },
      uRes: { value: new THREE.Vector2(1, 1) },
      uMouse: { value: new THREE.Vector2(0, 0) },
      uTime: { value: 0 },
      uCell: { value: CELL_BASE * dpr },
      uGlyphCount: { value: GLYPHS.length },
      uReveal: { value: 0 },
    };

    const scene = new THREE.Scene();
    const camera = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
    const quad = new THREE.Mesh(
      new THREE.PlaneGeometry(2, 2),
      new THREE.ShaderMaterial({ vertexShader: VERTEX, fragmentShader: FRAGMENT, uniforms })
    );
    scene.add(quad);

    const target = new THREE.Vector2(0, 0);
    let pointerSeen = false;
    const redraw = () => {
      const w = host.clientWidth;
      const h = host.clientHeight;
      renderer.setSize(w, h, false);
      uniforms.uRes.value.set(w * dpr, h * dpr);
      if (!pointerSeen) {
        // Rest position: dead center, so the text starts undistorted
        target.set(w * dpr * 0.5, h * dpr * 0.5);
        uniforms.uMouse.value.copy(target);
      }
      drawTextCanvas(textCanvas, w * dpr, h * dpr);
      drawGlyphAtlas(glyphCanvas);
      textTex.needsUpdate = true;
      glyphTex.needsUpdate = true;
    };
    redraw();
    // Redraw once the mono font is actually available
    document.fonts?.load('700 100px "IBM Plex Mono"').then(redraw).catch(() => {});

    const onMove = (e: PointerEvent) => {
      pointerSeen = true;
      const rect = host.getBoundingClientRect();
      target.set((e.clientX - rect.left) * dpr, (rect.height - (e.clientY - rect.top)) * dpr);
    };
    window.addEventListener("pointermove", onMove, { passive: true });

    const ro = new ResizeObserver(redraw);
    ro.observe(host);
    window.addEventListener("resize", redraw);

    let raf = 0;
    const start = performance.now();
    const tick = () => {
      raf = requestAnimationFrame(tick);
      const t = (performance.now() - start) / 1000;
      uniforms.uTime.value = t;
      uniforms.uReveal.value = Math.min(1, t / 1.4);
      uniforms.uMouse.value.lerp(target, 0.3);
      renderer.render(scene, camera);
    };
    tick();

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      window.removeEventListener("resize", redraw);
      window.removeEventListener("pointermove", onMove);
      renderer.dispose();
      quad.geometry.dispose();
      (quad.material as THREE.Material).dispose();
      textTex.dispose();
      glyphTex.dispose();
      host.removeChild(renderer.domElement);
    };
  }, []);

  return <div ref={hostRef} className="ascii-hero" aria-hidden="true" />;
}
