// The /procs 3D scene: a grid of glass cubes, and nothing moves without a reason.
//
//   district    one floor plate per domain: Windows (the host) and Linux (the
//               WSL guest). A dashed line on the floor tethers the guest to
//               vmmemWSL, the Windows process that is its virtual machine.
//   block       inside a district, the processes that share a parent program,
//               with the parent's name on the floor (procs-layout.js).
//   cube        one process. Height and inner glow = CPU (square root, so a
//               1% load shows); footprint = resident memory (log scale).
//   colour and  red with a diamond marker = alarm (unfamiliar), amber with a
//   marker      triangle = notice (new today), calm glass = seen before,
//               grey with dashed edges = not judged yet (procs-model.js).
//   top rim     started in the last RIM_MS; it does not move.
//   hollow      a watched process that went missing: a dashed outline in a
//               "Missing" block, the first (back-left) block of its district.
//   ghost       a start Sysmon recorded that no 500 ms look caught: a hollow
//               cube rises from its parent's block and fades.
//   motion      a start grows out of the floor, an exit sinks into it, a CPU
//               change eases the height. A re-laid-out block jumps rather
//               than slides. Idle is still; nothing loops.
//   grey scene  the feed is stale or down: the clock stops, so does motion.
//
// Draw calls: floor, plates, pools, cube backs, cube fronts, markers, tether.
// Everything per process is one InstancedMesh row; render on demand only.
import * as THREE from '/static/vendor/three.module.min.js';
import { cpuHeight, familyOf, gridLayout, memSide } from '/static/procs-layout.js';

const BIRTH_MS = 650, EXIT_MS = 650, GHOST_MS = 2200, FLASH_S = 1.2;
const RIM_MS = 5 * 60 * 1000;    // the "recently started" rim
const EASE = 9;                  // per second: heights
const GHOSTS_MAX = 48, GHOST_FRAME_MS = 50;
const LABELS_MAX = 18, BLOCK_LABELS_MAX = 14, BLOCK_LABEL_MIN = 4;
const SIDE = 0.86;               // world size of the largest footprint (cell pitch is 1)
const PALETTE_KEYS = ['bg', 'ink', 'ink-2', 'ink-3', 'win', 'lin', 'hot', 'warm', 'ghost', 'accent', 'new', 'recent'];
const MODE = { solid: 0, missing: 1, ghost: 2, unknown: 3 };
const SHAPE = { none: 0, alarm: 1, notice: 2 };
// how much of the verdict's colour fills the glass: a change must be findable among 300
const BODY = { alarm: 0.80, notice: 0.58, calm: 0.20, unknown: 0.08 };
const reducedMotion = matchMedia('(prefers-reduced-motion: reduce)');
// Colours are CSS tokens, used as given (sRGB in, sRGB out): no colour management.
THREE.ColorManagement.enabled = false;

// ---- shaders ------------------------------------------------------------------------

const GLSL_COMMON = `
  uniform float uLight; uniform vec3 uBg; uniform vec3 uInk;
  float gridLine(vec2 p){                       // cell borders at half-integers
    vec2 q = p - .5;
    vec2 g = abs(fract(q - .5) - .5) / max(fwidth(q), vec2(1e-4));
    return 1. - min(min(g.x, g.y), 1.);
  }
  vec3 sky(vec3 d){                             // what the glass reflects
    float h = clamp(d.y * .5 + .5, 0., 1.);
    vec3 dark = mix(vec3(.02, .03, .06), vec3(.20, .30, .52), smoothstep(.35, 1., h));
    dark += vec3(.7, .85, 1.) * pow(max(dot(d, normalize(vec3(-.35, .8, .45))), 0.), 40.) * 1.2;
    vec3 lite = mix(vec3(.80, .84, .90), vec3(1.), smoothstep(.3, .9, h));
    lite += pow(max(dot(d, normalize(vec3(-.35, .8, .45))), 0.), 30.) * .6;
    return mix(dark, lite, uLight);
  }`;

const CUBE_VERT = `
  attribute vec3 aTint; attribute vec4 aInfo; attribute vec3 aGlow;
  varying vec3 vLocal; varying vec3 vScale; varying vec3 vWorld; varying vec3 vN; varying vec3 vObjN;
  varying vec3 vTint; varying vec4 vInfo; varying vec3 vGlow;
  void main(){
    vec3 sc = vec3(length(instanceMatrix[0].xyz), length(instanceMatrix[1].xyz), length(instanceMatrix[2].xyz));
    vec4 w = modelMatrix * instanceMatrix * vec4(position, 1.);
    vLocal = position; vScale = sc; vWorld = w.xyz; vObjN = normal;
    vN = normalize(mat3(modelMatrix) * normal);
    vTint = aTint; vInfo = aInfo; vGlow = aGlow;
    gl_Position = projectionMatrix * viewMatrix * w;
  }`;

// aInfo: mode, birth time (s), emphasis (-1 dimmed, 0, 1 pointed at), recent-start rim
// aGlow: CPU glow 0..1, overall opacity, body tint strength (the verdict)
const CUBE_FRAG = `
  uniform float uTime; uniform float uBack; uniform vec3 uAccent;
  ${GLSL_COMMON}
  varying vec3 vLocal; varying vec3 vScale; varying vec3 vWorld; varying vec3 vN; varying vec3 vObjN;
  varying vec3 vTint; varying vec4 vInfo; varying vec3 vGlow;
  void main(){
    float mode = vInfo.x, emph = vInfo.z, rim = vInfo.w, glow = vGlow.x, fade = vGlow.y;
    vec3 an = abs(vObjN);
    // distance to the nearest edge of this face, in world units
    vec3 d = vec3((.5 - abs(vLocal.x)) * vScale.x, min(vLocal.y, 1. - vLocal.y) * vScale.y,
                  (.5 - abs(vLocal.z)) * vScale.z);
    float e = 1e3;
    if (an.x < .5) e = min(e, d.x);
    if (an.y < .5) e = min(e, d.y);
    if (an.z < .5) e = min(e, d.z);
    float aa = fwidth(e) * 1.2 + 1e-4;
    float hair = 1. - smoothstep(.010, .010 + aa, e);
    float bevel = 1. - smoothstep(0., .07, e);
    // dashed edges: not judged yet, missing, ghost
    float dashed = step(.5, mode);
    float dash = step(.45, fract((vWorld.x + vWorld.y + vWorld.z) * 4.));
    hair *= mix(1., dash, dashed);

    vec3 V = normalize(cameraPosition - vWorld);
    vec3 N = normalize(vN);
    float ndv = abs(dot(N, V));
    float F = .04 + .96 * pow(1. - ndv, 5.);
    float top = step(.5, vObjN.y);
    bool hollow = mode > .5 && mode < 2.5;

    vec3 ink = mix(vTint * 1.3 + .12, mix(vTint, uInk, .30) * .80, uLight);   // edge colour
    ink = mix(ink, uAccent, step(.5, emph) * .8);
    float edgeK = mix(.80, .62, uLight) * (1. + step(.5, emph) * .9);

    if (uBack > .5) {                       // the far faces, seen through the near ones
      if (hollow) { gl_FragColor = vec4(ink, hair * .45 * fade); return; }
      float a = (hair * .5 * edgeK + .06 + glow * .12) * fade;
      gl_FragColor = vec4(mix(vTint, ink, hair), a);
      return;
    }
    if (hollow) {
      float a = (hair * edgeK + bevel * .12) * fade;
      gl_FragColor = vec4(ink, a);
      return;
    }

    // the floor grid, bent through the glass
    vec3 R = refract(-V, N, .70);
    float t = vWorld.y / max(-R.y, .08);
    vec2 hit = vWorld.xz + R.xz * min(t, 6.);
    float g = gridLine(hit);
    vec3 behind = mix(uBg, uInk, g * mix(.22, .12, uLight));

    float k = clamp(vGlow.z + glow * .30, 0., .92);   // tint strength: the verdict, then load
    vec3 col = mix(behind, vTint, k);
    // inner glow for CPU, rising from the floor
    col += vTint * glow * (.25 + .75 * clamp(vLocal.y, 0., 1.)) * mix(.9, .35, uLight);
    // top faces catch the light; side faces shade by direction
    col *= mix(.86 + .14 * N.x, 1.08, top);
    col = mix(col, col + .10 * (1. - uLight), top);
    // reflection of the sky, strongest at grazing angles
    col += sky(reflect(-V, N)) * F * mix(.55, .45, uLight);
    // soft bevel catches a highlight; hairline edge in the cube's ink
    col += mix(vec3(.85, .92, 1.), vec3(1.), uLight) * bevel * bevel * max(N.y, .25) * mix(.16, .30, uLight);
    col = mix(col, ink, hair * edgeK);
    // recently started: a bright rim on the top face
    float ring = top * rim * (1. - smoothstep(.035, .035 + aa, e));
    col = mix(col, uAccent * mix(1.25, .9, uLight), ring);
    // a start: a brief flash
    float since = uTime - vInfo.y;
    float flash = since >= 0. ? exp(-since * 3.5) : 0.;
    col += vTint * flash * .8;

    float alpha = mix(.30, .55, uLight) + k * .35 + F * .25 + hair * edgeK + ring + flash * .3;
    if (emph < -.5) { col = mix(col, uBg, .55); alpha *= .22; }
    gl_FragColor = vec4(col, clamp(alpha, 0., 1.) * fade);
  }`;

const POOL_VERT = `
  attribute vec3 aTint; attribute vec2 aGlow;
  varying vec2 vUv; varying vec3 vTint; varying vec2 vGlow;
  void main(){ vUv = uv; vTint = aTint; vGlow = aGlow;
    gl_Position = projectionMatrix * viewMatrix * modelMatrix * instanceMatrix * vec4(position, 1.); }`;
// light: a soft contact shadow; dark: a pool of the cube's own light
const POOL_FRAG = `
  uniform float uLight;
  varying vec2 vUv; varying vec3 vTint; varying vec2 vGlow;
  void main(){
    vec2 q = abs(vUv - .5) * 2.;
    float r = length(max(q - .30, 0.)) / .70;
    float fall = pow(clamp(1. - r, 0., 1.), 2.2);
    float shadow = fall * (.16 + vGlow.x * .10);
    float pool = fall * (.05 + vGlow.x * .55);
    vec3 col = mix(vTint, vec3(0.), uLight);
    gl_FragColor = vec4(col, mix(pool, shadow, uLight) * vGlow.y);
  }`;

const PLATE_VERT = `
  attribute vec3 aTint; attribute vec3 aPlate;
  varying vec2 vP; varying vec3 vTint; varying vec3 vPlate;
  void main(){ vP = (uv - .5) * aPlate.xy; vTint = aTint; vPlate = aPlate;
    gl_Position = projectionMatrix * viewMatrix * modelMatrix * instanceMatrix * vec4(position, 1.); }`;
// aPlate: width, depth (world), kind (0 district, 1 block)
const PLATE_FRAG = `
  uniform float uLight; uniform vec3 uBg;
  varying vec2 vP; varying vec3 vTint; varying vec3 vPlate;
  void main(){
    float block = vPlate.z;
    float rad = mix(.55, .28, block);
    vec2 b = vPlate.xy * .5 - rad;
    float dist = length(max(abs(vP) - b, 0.)) - rad;     // < 0 inside
    float aa = length(fwidth(vP)) * .75 + 1e-4;      // never zero: smoothstep(0, 0) is undefined
    float inside = 1. - smoothstep(-aa, aa, dist);
    float line = 1. - smoothstep(0., aa * 1.5, abs(dist + aa));
    vec3 fillC = mix(vTint * .55, vec3(1.), uLight);
    float fillA = mix(mix(.07, .035, block), mix(.70, .38, block), uLight);
    // the district plate lifts toward its back edge, like a panel under a lamp
    fillA *= mix(1., .85 + .15 * smoothstep(-vPlate.y * .5, vPlate.y * .5, -vP.y), 1. - block);
    vec3 lineC = mix(vTint * .9, mix(vTint, vec3(.55, .58, .64), .55), uLight);
    float lineA = mix(mix(.45, .22, block), mix(.30, .18, block), uLight);
    vec3 col = mix(fillC, lineC, line);
    gl_FragColor = vec4(col, max(inside * fillA, line * lineA));
  }`;

const FLOOR_VERT = `varying vec3 vW; void main(){ vec4 w = modelMatrix * vec4(position, 1.); vW = w.xyz;
  gl_Position = projectionMatrix * viewMatrix * w; }`;
const FLOOR_FRAG = `
  uniform vec3 uCenter; uniform float uRadius;
  ${GLSL_COMMON}
  varying vec3 vW;
  void main(){
    float g = gridLine(vW.xz);
    float r = length((vW.xz - uCenter.xz) / uRadius);
    float fadeOut = 1. - smoothstep(.55, 1.15, r);
    // fine lines only while they are wider than a pixel apart
    float dens = 1. - smoothstep(.25, .6, max(fwidth(vW.x), fwidth(vW.z)));
    gl_FragColor = vec4(uInk, g * fadeOut * dens * mix(.11, .085, uLight));
  }`;

const MARK_VERT = `
  attribute vec3 aTint; attribute float aShape;
  uniform vec2 uRes; uniform float uSize;
  varying vec2 vP; varying vec3 vTint; varying float vShape;
  void main(){
    vec4 clip = projectionMatrix * viewMatrix * modelMatrix * vec4(instanceMatrix[3].xyz, 1.);
    clip.xy += position.xy * uSize * 2. / uRes * clip.w;
    vP = position.xy * 2.; vTint = aTint; vShape = aShape;
    gl_Position = clip;
  }`;
// diamond with "!" for alarm, triangle with a dot for notice; outlined in the
// background colour so either shape reads on both themes
const MARK_FRAG = `
  uniform vec3 uBg;
  varying vec2 vP; varying vec3 vTint; varying float vShape;
  float sdTri(vec2 p){ return max(abs(p.x) * .866 + p.y * .5 - .425, -p.y - .55); }
  void main(){
    vec2 p = vP;
    float dist = vShape < 1.5 ? (abs(p.x) + abs(p.y) - .82) * .7071 : sdTri(p);
    float aa = length(fwidth(p)) * .6 + 1e-4;
    float fill = 1. - smoothstep(-aa, aa, dist);
    float outline = 1. - smoothstep(-aa, aa, dist - .12);
    if (outline < .01) discard;
    // the glyph
    float bar = step(abs(p.x), .085) * step(-.06, p.y) * step(p.y, .42);
    float dot1 = 1. - smoothstep(.10, .10 + aa, length(p - vec2(0., -.24)));
    float glyph = vShape < 1.5 ? max(bar, dot1) : 1. - smoothstep(.12, .12 + aa, length(p - vec2(0., -.10)));
    vec3 col = mix(uBg, vTint, fill);
    col = mix(col, uBg, glyph * fill);
    gl_FragColor = vec4(col, outline);
  }`;

// ---- the scene ----------------------------------------------------------------------

export class ProcScene {
  constructor(canvas, labelBox, state) {
    this.canvas = canvas;
    this.labelBox = labelBox;
    this.state = state;
    this.palette = {};
    this.query = '';
    this.onlyChanges = false;
    this.hovered = null;
    this.focused = null;
    this.order = [];           // live processes drawn this frame
    this.items = [];           // every cube row drawn, by instance index
    this.parents = new Map();  // id -> parent process
    this.grid = { blocks: [], domains: {}, cells: new Map() };
    this.ghostPool = [];
    this.fitted = false;
    this.dirty = true;
    this.animating = 0;
    this.clock = performance.now();   // stops while the feed is not live
    this.offset = { x: 0, z: 0 };
    this.orbit = { theta: 1.05, phi: 0.98, dist: 90, tx: 0, ty: 0, tz: 0, goal: null };
    this.stats = { frames: 0, ms: 0, calls: 0 };
    this.tmp = { m4: new THREE.Matrix4(), q: new THREE.Quaternion(), v3: new THREE.Vector3(),
      s3: new THREE.Vector3(), col: new THREE.Color(), col2: new THREE.Color() };
    this.build();
    this.readPalette();
  }

  // ---- construction ---------------------------------------------------------------

  build() {
    // alpha: the page's own gradient is the sky behind the floor
    this.renderer = new THREE.WebGLRenderer({ canvas: this.canvas, antialias: true, alpha: true,
      powerPreference: 'low-power' });
    this.renderer.setClearColor(0x000000, 0);
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.outputColorSpace = THREE.LinearSRGBColorSpace;
    this.scene = new THREE.Scene();
    this.camera = new THREE.PerspectiveCamera(30, 1, 0.5, 3000);
    const U = this.U = {
      uLight: { value: 1 }, uBg: { value: new THREE.Color() }, uInk: { value: new THREE.Color() },
      uAccent: { value: new THREE.Color() }, uTime: { value: 0 }, uRes: { value: new THREE.Vector2(1, 1) },
    };
    const mat = (vertexShader, fragmentShader, extra = {}, opts = {}) => new THREE.ShaderMaterial({
      vertexShader, fragmentShader, transparent: true, depthWrite: false,
      uniforms: { ...U, ...extra }, ...opts });

    // floor grid
    this.floorMat = mat(FLOOR_VERT, FLOOR_FRAG, { uCenter: { value: new THREE.Vector3() }, uRadius: { value: 50 } });
    const floorGeo = new THREE.PlaneGeometry(1, 1);
    floorGeo.rotateX(-Math.PI / 2);
    this.floor = new THREE.Mesh(floorGeo, this.floorMat);
    this.floor.renderOrder = 0;
    this.scene.add(this.floor);

    // plates: one per district and one per block
    const plateGeo = new THREE.PlaneGeometry(1, 1);
    plateGeo.rotateX(-Math.PI / 2);
    this.plates = this.instanced(plateGeo, mat(PLATE_VERT, PLATE_FRAG), 128, { aTint: 3, aPlate: 3 });
    this.plates.renderOrder = 1;

    // pools of light (dark) or contact shadows (light)
    const poolGeo = new THREE.PlaneGeometry(1, 1);
    poolGeo.rotateX(-Math.PI / 2);
    this.poolMat = mat(POOL_VERT, POOL_FRAG);
    this.pools = this.instanced(poolGeo, this.poolMat, 1024, { aTint: 3, aGlow: 2 });
    this.pools.renderOrder = 2;

    // cubes: one geometry, drawn twice (far faces, then near faces as glass)
    this.cubeGeo = new THREE.BoxGeometry(1, 1, 1);
    this.cubeGeo.translate(0, 0.5, 0);
    this.backMat = mat(CUBE_VERT, CUBE_FRAG, { uBack: { value: 1 } }, { side: THREE.BackSide });
    this.frontMat = mat(CUBE_VERT, CUBE_FRAG, { uBack: { value: 0 } }, { side: THREE.FrontSide });
    this.cubesBack = this.instanced(this.cubeGeo, this.backMat, 1024, { aTint: 3, aInfo: 4, aGlow: 3 });
    this.cubes = new THREE.InstancedMesh(this.cubesBack.geometry, this.frontMat, 1024);
    this.cubes.instanceMatrix = this.cubesBack.instanceMatrix;
    this.cubes.frustumCulled = false;
    this.cubesBack.renderOrder = 3; this.cubes.renderOrder = 4;
    this.scene.add(this.cubes);

    // verdict markers, billboarded, never hidden behind a cube
    const markGeo = new THREE.PlaneGeometry(1, 1);
    this.markMat = mat(MARK_VERT, MARK_FRAG, { uSize: { value: 12 } }, { depthTest: false });
    this.marks = this.instanced(markGeo, this.markMat, 256, { aTint: 3, aShape: 1 });
    this.marks.renderOrder = 6;

    // the tether from vmmemWSL to the guest's district
    const tGeo = new THREE.BufferGeometry().setFromPoints([new THREE.Vector3(), new THREE.Vector3(1, 0, 0)]);
    this.tether = new THREE.Line(tGeo, new THREE.LineDashedMaterial({ dashSize: 0.5, gapSize: 0.35,
      transparent: true, opacity: 0.6, depthWrite: false }));
    this.tether.renderOrder = 2;
    this.tether.visible = false;
    this.scene.add(this.tether);

    this.ray = new THREE.Raycaster();
    this.ndc = new THREE.Vector2();
  }

  // An InstancedMesh with its own per-instance attributes on a copy of the geometry.
  instanced(geo, material, capacity, attrs) {
    const g = geo.clone();
    for (const [name, size] of Object.entries(attrs)) {
      g.setAttribute(name, new THREE.InstancedBufferAttribute(new Float32Array(capacity * size), size)
        .setUsage(THREE.DynamicDrawUsage));
    }
    const mesh = new THREE.InstancedMesh(g, material, capacity);
    mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    mesh.frustumCulled = false;
    mesh.count = 0;
    this.scene.add(mesh);
    return mesh;
  }

  // Grow an instanced mesh (and its twin) when the table outgrows it.
  ensureCapacity(n) {
    const cap = this.cubesBack.instanceMatrix.count;
    if (n <= cap) return;
    const size = 2 ** Math.ceil(Math.log2(n));
    const old = [this.cubesBack, this.cubes, this.pools];
    for (const m of old) { this.scene.remove(m); m.dispose(); }
    this.cubesBack = this.instanced(this.cubeGeo, this.backMat, size, { aTint: 3, aInfo: 4, aGlow: 3 });
    this.cubes = new THREE.InstancedMesh(this.cubesBack.geometry, this.frontMat, size);
    this.cubes.instanceMatrix = this.cubesBack.instanceMatrix;
    this.cubes.frustumCulled = false;
    this.cubesBack.renderOrder = 3; this.cubes.renderOrder = 4;
    this.scene.add(this.cubes);
    this.pools = this.instanced(old[2].geometry, this.poolMat, size, { aTint: 3, aGlow: 2 });
    this.pools.renderOrder = 2;
    old[0].geometry.dispose(); old[2].geometry.dispose();   // the twin shares the first
  }

  readPalette() {
    const s = getComputedStyle(document.documentElement);
    for (const k of PALETTE_KEYS) this.palette[k] = new THREE.Color(s.getPropertyValue('--' + k).trim() || '#888');
    const bg = this.palette.bg;
    const light = (0.2126 * bg.r + 0.7152 * bg.g + 0.0722 * bg.b) > 0.5;
    this.light = light;
    this.U.uLight.value = light ? 1 : 0;
    this.U.uBg.value.copy(bg);
    this.U.uInk.value.copy(this.palette.ink);
    this.U.uAccent.value.copy(this.palette.accent);
    this.poolMat.blending = light ? THREE.NormalBlending : THREE.AdditiveBlending;
    this.poolMat.needsUpdate = true;
    this.tether.material.color.copy(this.palette['ink-3']);
    this.wake();
  }

  wake() { this.dirty = true; }

  // Screen space the panels cover on the left and right: the scene is centred
  // in what is left, and F fits it there.
  setInsets(left, right) {
    this.insets = { left, right };
    this.resize(innerWidth, innerHeight);
  }

  resize(w, h) {
    this.renderer.setSize(w, h, false);
    this.camera.aspect = w / h;
    const ins = this.insets || { left: 0, right: 0 };
    this.camera.setViewOffset(w, h, -(ins.left - ins.right) / 2, 0, w, h);
    this.camera.updateProjectionMatrix();
    const pr = this.renderer.getPixelRatio();
    this.U.uRes.value.set(w * pr, h * pr);
    this.markMat.uniforms.uSize.value = 12 * pr;
    this.wake();
  }

  // ---- layout -------------------------------------------------------------------------

  layout() {
    const state = this.state;
    state.structural = false;
    const alive = [];
    for (const p of state.procs.values()) if (!p.dying && (p.h === 'win' || p.h === 'lin')) alive.push(p);
    // parents: same rule as before, a parent must predate its child
    const byPid = { win: new Map(), lin: new Map() };
    for (const p of alive) byPid[p.h].set(p.pid, p);
    this.parents = new Map();
    const items = [];
    for (const p of alive) {
      const parent = byPid[p.h].get(p.ppid);
      const ok = parent && parent !== p && parent.created <= p.created + 1000 ? parent : null;
      if (ok) this.parents.set(p.id, ok);
      items.push({ id: p.id, h: p.h, family: familyOf(ok), order: p.created });
    }
    // missing watched processes: hollow cubes in their own block
    this.missing = [];
    for (const h of ['win', 'lin']) {
      for (const name of state.missingNow[h] || []) {
        const id = 'missing|' + h + '|' + name;
        this.missing.push({ id, h, name });
        items.push({ id, h, family: '#missing', order: 0 });
      }
    }
    const grid = gridLayout(items);
    // Grid cell (col, row) is world (x, z): the origin never shifts, so a
    // table that grows does not move every cube; the camera does the framing.
    let maxCol = 0, maxRow = 0;
    for (const d of Object.values(grid.domains)) { maxCol = Math.max(maxCol, d.col + d.cols); maxRow = Math.max(maxRow, d.rows); }
    this.offset = { x: 0, z: 0 };
    this.grid = grid;
    for (const p of alive) {
      const c = grid.cells.get(p.id);
      // a cube moves only when its block is re-laid out, and then it jumps:
      // sliding blocks would read as activity (Jev: block_reflow misread 0.74)
      p.tx = c.col + this.offset.x; p.tz = c.row + this.offset.z;
      p.x = p.tx; p.z = p.tz;
    }
    for (const m of this.missing) {
      const c = grid.cells.get(m.id);
      m.x = c.col + this.offset.x; m.z = c.row + this.offset.z;
    }
    this.layoutPlates();
    // the floor follows the grid
    const w = Math.max(20, maxCol + 24), dz = Math.max(20, maxRow + 24);
    this.floor.scale.set(w * 2, 1, dz * 2);
    this.floor.position.set(maxCol / 2, 0, maxRow / 2);
    this.floorMat.uniforms.uCenter.value.set(maxCol / 2, 0, maxRow / 2);
    this.floorMat.uniforms.uRadius.value = Math.max(w, dz) * 0.62;
    // Frame the scene once, when every present domain has reported; after that
    // the camera moves only when the viewer asks (drag, wheel, keys, F, double-click).
    const reported = ['win', 'lin'].every((h) => state.sources[h]
      && (state.sources[h].state === 'absent' || grid.domains[h]));
    if (!this.fitted && reported) this.fitted = this.fit();
  }

  layoutPlates() {
    const { m4, q, v3, s3 } = this.tmp;
    const mesh = this.plates, tint = mesh.geometry.attributes.aTint.array, plate = mesh.geometry.attributes.aPlate.array;
    let i = 0;
    const put = (col, row, cols, rows, pad, color, kind) => {
      if (i >= mesh.instanceMatrix.count) return;
      const w = cols + pad * 2, d = rows + pad * 2;
      const cx = col + this.offset.x + (cols - 1) / 2, cz = row + this.offset.z + (rows - 1) / 2;
      m4.compose(v3.set(cx, kind ? 0.004 : 0.002, cz), q, s3.set(w, 1, d));
      mesh.setMatrixAt(i, m4);
      tint.set([color.r, color.g, color.b], i * 3);
      plate.set([w, d, kind], i * 3);
      i++;
    };
    for (const [h, d] of Object.entries(this.grid.domains)) put(d.col, d.row, d.cols, d.rows, 1.1, this.palette[h], 0);
    for (const b of this.grid.blocks) {
      const color = b.key === '#missing' ? this.palette.hot : this.palette[b.h];
      put(b.col, b.row, b.cols, b.rows, 0.42, color, 1);
    }
    mesh.count = i;
    mesh.instanceMatrix.needsUpdate = true;
    mesh.geometry.attributes.aTint.needsUpdate = true;
    mesh.geometry.attributes.aPlate.needsUpdate = true;
  }

  parentOf(p) {
    const parent = this.parents.get(p.id);
    return parent && this.state.procs.has(parent.id) ? parent : null;
  }

  // World bounds of what is laid out, one cell of margin: [minX, maxX, minZ, maxZ].
  bounds() {
    const ds = Object.values(this.grid.domains);
    if (!ds.length) return null;
    let minX = Infinity, maxX = -Infinity, maxZ = -Infinity;
    for (const d of ds) {
      minX = Math.min(minX, d.col); maxX = Math.max(maxX, d.col + d.cols - 1); maxZ = Math.max(maxZ, d.rows - 1);
    }
    return [minX + this.offset.x - 1, maxX + this.offset.x + 1, this.offset.z - 1, maxZ + this.offset.z + 1];
  }

  fit() {
    const b = this.bounds();
    if (!b) return false;
    const [minX, maxX, minZ, maxZ] = b;
    const o = this.orbit;
    o.theta = 1.05; o.phi = 0.98;
    const cx = (minX + maxX) / 2, cz = (minZ + maxZ) / 2;
    // the largest view of the grid's box (floor to a typical height) that
    // stays inside the free screen: between the side panels, above the legend
    const ins = this.insets || { left: 0, right: 0 };
    const W = innerWidth, H = innerHeight;
    const lim = [-1 + 2 * (ins.left + 24) / W, 1 - 2 * (ins.right + 24) / W, -1 + 2 * 110 / H, 1 - 2 * 48 / H];
    const corners = [];
    for (const x of [minX, maxX]) for (const z of [minZ, maxZ]) for (const y of [0, 2.5]) corners.push([x, y, z]);
    const saved = { tx: o.tx, tz: o.tz, dist: o.dist };
    o.tx = cx; o.tz = cz;
    const fits = (dist) => {
      o.dist = dist;
      this.placeCamera();
      for (const [x, y, z] of corners) {
        const v = this.tmp.v3.set(x, y, z).project(this.camera);
        if (v.z > 1 || v.x < lim[0] || v.x > lim[1] || v.y < lim[2] || v.y > lim[3]) return false;
      }
      return true;
    };
    let lo = 8, hi = 1200;
    for (let i = 0; i < 24; i++) { const mid = (lo + hi) / 2; if (fits(mid)) hi = mid; else lo = mid; }
    o.tx = saved.tx; o.tz = saved.tz;
    o.dist = hi;
    o.goal = { x: cx, y: 0, z: cz };
    if (!this.fitted) { o.tx = cx; o.tz = cz; }          // the first framing does not fly in
    this.wake();
    return true;
  }

  focus(p) {
    this.focused = p;
    if (Number.isFinite(p.x)) this.orbit.goal = { x: p.x, y: 0, z: p.z };
    this.orbit.dist = Math.min(this.orbit.dist, 46);
    this.wake();
  }

  // ---- drawing ------------------------------------------------------------------------

  tintOf(p, out) {
    const { palette } = this;
    if (p.level === 'alarm') return out.copy(palette.new);
    if (p.level === 'notice') return out.copy(palette.recent);
    if (p.level === 'unknown') return out.copy(palette['ink-3']);
    // calm: clear glass with a hint of the domain's colour
    return out.copy(palette[p.h]).lerp(this.tmp.col2.copy(palette['ink-3']), this.light ? 0.5 : 0.45);
  }

  emphasis(p) {
    if (p === this.hovered || p === this.focused) return 1;
    if (this.query && !this.state.matches(p, this.query)) return -1;
    if (this.onlyChanges && p.level !== 'alarm' && p.level !== 'notice') return -1;
    return 0;
  }

  draw(t, dt) {
    const { state, tmp: { m4, q, v3, s3, col } } = this;
    const motion = !reducedMotion.matches;
    const k = motion ? Math.min(1, dt * EASE) : 1;
    this.animating = 0;
    this.order = [];
    for (const p of [...state.procs.values()]) {
      if (p.dying && t - p.dyingAt > EXIT_MS) state.remove(p.id);
      else this.order.push(p);
    }
    // missing changed (tally runs once a second): lay out again
    const sig = [...(state.missingNow.win || []), '|', ...(state.missingNow.lin || [])].join(',');
    if (sig !== this.lastMissing) { this.lastMissing = sig; this.layout(); }
    if (state.structural) this.layout();

    const items = [];
    for (const p of this.order) {
      if (!Number.isFinite(p.x)) continue;
      // a CPU change eases the height; nothing else moves a standing cube
      const th = cpuHeight(p.cpu);
      if (!Number.isFinite(p.hh)) p.hh = th;
      if (Math.abs(th - p.hh) > 0.003) { p.hh += (th - p.hh) * k; this.animating++; } else p.hh = th;
      let grow = 1;
      if (p.born && motion && t - p.bornAt < BIRTH_MS) grow = easeOut((t - p.bornAt) / BIRTH_MS);
      if (p.born && t - p.bornAt < FLASH_S * 1000) this.animating++;     // the flash fades out in the shader
      if (p.dying) { grow = motion ? Math.max(0, 1 - easeOut((t - p.dyingAt) / EXIT_MS)) : 0; this.animating++; }
      const side = memSide(p.rss) * SIDE;
      const tint = this.tintOf(p, col).clone();
      const recent = p.born && t - p.bornAt < RIM_MS ? 1 : 0;
      items.push({ p, kind: 'proc', x: p.x, z: p.z, y: 0, w: side, h: Math.max(0.02, p.hh * grow),
        tint, mode: p.level === 'unknown' ? MODE.unknown : MODE.solid,
        born: p.born && motion ? p.bornAt / 1000 : -100, emph: this.emphasis(p), rim: recent,
        glow: Math.min(1, Math.sqrt(p.cpu / 50)), fade: 1, body: BODY[p.level] ?? BODY.calm });
    }
    for (const m of this.missing || []) {
      items.push({ kind: 'missing', name: m.name, x: m.x, z: m.z, y: 0, w: SIDE * 0.7, h: 0.9,
        tint: this.palette.hot.clone(), mode: MODE.missing, born: -100, emph: 0, rim: 0, glow: 0, fade: 1, body: 0 });
    }
    // ghosts: rise and fade
    this.ghostOnly = this.animating === 0;
    this.ghostPool = this.ghostPool.filter((g) => t - g.at < GHOST_MS);
    for (const g of this.ghostPool) {
      const u = (t - g.at) / GHOST_MS;
      items.push({ kind: 'ghost', x: g.x, z: g.z, y: g.y + (motion ? easeOut(u) * 2.2 : 0.4), w: SIDE * 0.62, h: SIDE * 0.62,
        tint: g.tint, mode: MODE.ghost, born: -100, emph: 0, rim: 0, glow: 0, fade: 1 - u * u, body: 0 });
      this.animating++;
    }
    // far to near, so the glass blends in order
    const cam = this.camera.position;
    for (const it of items) it.d = (it.x - cam.x) ** 2 + (it.z - cam.z) ** 2 + (it.h / 2 - cam.y) ** 2;
    items.sort((a, b) => b.d - a.d);
    this.items = items;

    this.ensureCapacity(items.length + 1);
    const back = this.cubesBack, ga = back.geometry.attributes;
    const pools = this.pools, pa = pools.geometry.attributes;
    const marks = this.marks, ma = marks.geometry.attributes;
    let mi = 0;
    items.forEach((it, i) => {
      m4.compose(v3.set(it.x, it.y, it.z), q, s3.set(it.w, it.h, it.w));
      back.setMatrixAt(i, m4);
      ga.aTint.array.set([it.tint.r, it.tint.g, it.tint.b], i * 3);
      ga.aInfo.array.set([it.mode, it.born, it.emph, it.rim], i * 4);
      ga.aGlow.array.set([it.glow, it.fade, it.body], i * 3);
      const pw = it.kind === 'ghost' ? 0 : it.w * 2.3;
      m4.compose(v3.set(it.x, 0.006, it.z), q, s3.set(pw, 1, pw));
      pools.setMatrixAt(i, m4);
      pa.aTint.array.set([it.tint.r, it.tint.g, it.tint.b], i * 3);
      pa.aGlow.array.set([it.kind === 'proc' ? it.glow : 0, it.emph < 0 ? 0.25 : it.kind === 'missing' ? 0.4 : 1], i * 2);
      const lvl = it.p && it.p.level;
      if ((lvl === 'alarm' || lvl === 'notice') && !it.p.dying && mi < marks.instanceMatrix.count) {
        m4.makeTranslation(it.x, it.h + 0.75, it.z);
        marks.setMatrixAt(mi, m4);
        ma.aTint.array.set([it.tint.r, it.tint.g, it.tint.b], mi * 3);
        ma.aShape.array[mi] = lvl === 'alarm' ? SHAPE.alarm : SHAPE.notice;
        mi++;
      }
    });
    back.count = this.cubes.count = pools.count = items.length;
    marks.count = mi;
    back.instanceMatrix.needsUpdate = true;
    for (const a of [ga.aTint, ga.aInfo, ga.aGlow, pa.aTint, pa.aGlow, ma.aTint, ma.aShape]) a.needsUpdate = true;
    pools.instanceMatrix.needsUpdate = true;
    marks.instanceMatrix.needsUpdate = true;
    this.cubes.computeBoundingSphere();   // picking tests this, then each box

    // tether: vmmemWSL to the guest's district
    const vm = this.order.find((p) => p.h === 'win' && /^vmmem(WSL)?$/i.test(p.name) && !p.dying);
    const lin = this.grid.domains.lin;
    this.tether.visible = !!(vm && lin && Number.isFinite(vm.x));
    if (this.tether.visible) {
      const pos = this.tether.geometry.attributes.position;
      pos.setXYZ(0, vm.x, 0.01, vm.z);
      pos.setXYZ(1, lin.col + this.offset.x - 0.6, 0.01, this.offset.z - 0.6);
      pos.needsUpdate = true;
      this.tether.computeLineDistances();
    }
  }

  // New ghosts from the state. (No alarm beat: a marker is drawn instead,
  // so nothing loops while an alarm stands.)
  pulses(now, live) {
    if (!live) return;
    for (const g of this.state.ghosts.splice(0)) {
      if (this.ghostPool.length >= GHOSTS_MAX) this.ghostPool.shift();
      const parent = g.parent && Number.isFinite(g.parent.x) ? g.parent : null;
      const d = this.grid.domains[g.h];
      const x = parent ? parent.x : d ? d.col + this.offset.x - 1.2 : 0;
      const z = parent ? parent.z : d ? this.offset.z - 1.2 : 0;
      const tint = (g.level === 'alarm' ? this.palette.new : g.level === 'notice' ? this.palette.recent
        : this.palette.ghost).clone();
      // one rising ghost per spot at a time: a parent that starts a child every
      // few hundred ms (container health checks) shows one, not a column
      const same = this.ghostPool.find((q) => q.x === x && q.z === z && now - q.at < GHOST_MS * 0.6);
      if (same) { if (g.level === 'alarm' || g.level === 'notice') same.tint = tint; continue; }
      this.ghostPool.push({ at: now, x, z, y: parent ? (parent.hh || 0.2) + 0.3 : 0.3, tint });
      this.wake();
    }
  }

  // One rendered frame when something moved. `live` false freezes motion.
  frame(now, dt, live) {
    if (live) this.clock = now;
    const t = this.clock;
    const o = this.orbit;
    if (o.goal) {
      const kk = reducedMotion.matches ? 1 : Math.min(1, dt * 5);
      o.tx += (o.goal.x - o.tx) * kk; o.tz += (o.goal.z - o.tz) * kk;
      if (Math.abs(o.goal.x - o.tx) + Math.abs(o.goal.z - o.tz) < 0.02) { o.tx = o.goal.x; o.tz = o.goal.z; o.goal = null; }
      this.dirty = true;
    }
    if (this.state.structural) this.dirty = true;
    // the "recently started" rim expires by time alone: one quiet redraw every 10 s
    if (live && now - (this.drawnAt || 0) > 10000) this.dirty = true;
    if (!this.dirty && !this.animating) return;
    // when only ghosts move, 20 frames a second is enough
    if (!this.dirty && this.ghostOnly && now - (this.drawnAt || 0) < GHOST_FRAME_MS) return;
    this.drawnAt = now;
    const t0 = performance.now();
    this.placeCamera();
    this.draw(t, live ? dt : 0);
    if (!live) this.animating = 0;
    this.U.uTime.value = t / 1000;
    this.renderer.render(this.scene, this.camera);
    this.renderLabels();
    this.dirty = false;
    this.stats.frames++;
    this.stats.ms = performance.now() - t0;
    this.stats.calls = this.renderer.info.render.calls;
  }

  placeCamera() {
    const { theta, phi, dist, tx, ty, tz } = this.orbit;
    this.camera.position.set(tx + dist * Math.sin(phi) * Math.cos(theta), ty + dist * Math.cos(phi),
      tz + dist * Math.sin(phi) * Math.sin(theta));
    this.camera.lookAt(tx, ty, tz);
    this.camera.updateMatrixWorld();
  }

  project(x, y, z) {
    const v3 = this.tmp.v3.set(x, y, z).project(this.camera);
    if (v3.z > 1 || v3.z < -1) return null;
    return [(v3.x + 1) / 2 * innerWidth, (1 - v3.y) / 2 * innerHeight];
  }

  renderLabels() {
    // Candidates in priority order; a label that would overlap one already
    // placed is dropped (the hovered or focused process always shows).
    const cands = [];
    for (const [h, d] of Object.entries(this.grid.domains)) {
      cands.push({ cls: 'district', x: d.col + this.offset.x - 1.2, y: 0, z: this.offset.z - 1.7, align: 0,
        text: `${h === 'win' ? 'Windows' : 'Linux · WSL'}<span class="num">${d.n - (this.missing || []).filter((m) => m.h === h).length}</span>`,
        size: 15, len: 14 });
    }
    const alive = this.order.filter((p) => !p.dying && Number.isFinite(p.x));
    const proc = (p, force) => {
      const flagged = p.level === 'alarm' || p.level === 'notice';
      const cpu = p.cpu >= 0.5 ? ` <span class="num">${p.cpu.toFixed(1)}%</span>` : '';
      cands.push({ cls: 'proc', level: flagged ? p.level : '', x: p.x, y: (p.hh || 0.2) + (flagged ? 1.35 : 0.3), z: p.z,
        align: 0.5, text: esc(p.name) + cpu, size: 11, len: p.name.length + (cpu ? 6 : 0), force });
    };
    if (this.hovered) proc(this.hovered, true);
    if (this.focused && this.focused !== this.hovered && this.state.procs.has(this.focused.id)) proc(this.focused, true);
    for (const m of this.missing || []) {
      cands.push({ cls: 'proc miss', x: m.x, y: 1.2, z: m.z, align: 0.5, text: 'Missing: ' + esc(m.name), size: 11,
        len: m.name.length + 9, force: true });
    }
    for (const p of alive) if (p.level === 'alarm') proc(p);
    for (const p of alive) if (p.level === 'notice') proc(p);
    if (this.query) for (const p of alive) if (this.state.matches(p, this.query)) proc(p);
    const blocks = this.grid.blocks.filter((b) => b.n >= BLOCK_LABEL_MIN || b.key === '#missing')
      .sort((a, b) => b.n - a.n).slice(0, BLOCK_LABELS_MAX);
    for (const b of blocks) {
      const name = b.key === '#missing' ? 'Missing' : b.key === '' ? 'Other parents' : b.key === '(no parent)'
        ? 'Parent exited' : b.key;
      cands.push({ cls: 'block' + (b.key === '#missing' ? ' miss' : ''), x: b.col + this.offset.x - 0.45, y: 0,
        z: b.row + this.offset.z - 0.6, align: 0, text: `${esc(name)}<span class="num">${b.n}</span>`, size: 10.5,
        len: name.length + 4, caps: true });
    }
    if (!this.onlyChanges) for (const p of alive.filter((x) => x.cpu >= 0.5).sort((a, b) => b.cpu - a.cpu).slice(0, 5)) proc(p);

    const placed = [], html = [], seen = new Set();
    for (const c of cands) {
      const key = c.cls + c.x + ',' + c.z;
      if (seen.has(key)) continue;
      const at = this.project(c.x, c.y, c.z);
      if (!at) continue;
      const w = c.len * c.size * (c.caps ? 0.68 : 0.58) + 14, hgt = c.size + 8;
      const r = [at[0] - w * c.align, at[1] - hgt, at[0] - w * c.align + w, at[1]];
      if (!c.force && placed.some((q) => r[0] < q[2] && r[2] > q[0] && r[1] < q[3] && r[3] > q[1])) continue;
      if (placed.length >= LABELS_MAX + BLOCK_LABELS_MAX + 2 && !c.force) break;
      placed.push(r); seen.add(key);
      html.push(`<div class="${c.cls}"${c.level ? ` data-level="${c.level}"` : ''} style="left:${at[0].toFixed(0)}px;`
        + `top:${at[1].toFixed(0)}px">${c.text}</div>`);
    }
    this.labelBox.innerHTML = html.join('');
  }

  // ---- input --------------------------------------------------------------------------

  bindInput(onPick, onHover) {
    const c = this.canvas, o = this.orbit;
    let drag = null;
    c.addEventListener('pointerdown', (e) => {
      drag = { x: e.clientX, y: e.clientY, moved: false, pan: e.button === 2 || e.shiftKey };
      c.setPointerCapture(e.pointerId); c.classList.add('dragging');
    });
    c.addEventListener('contextmenu', (e) => e.preventDefault());
    c.addEventListener('pointerup', (e) => {
      c.classList.remove('dragging');
      if (drag && !drag.moved) onPick(this.pick(e.clientX, e.clientY));
      drag = null; this.wake();
    });
    c.addEventListener('pointermove', (e) => {
      if (drag) {
        const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
        if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
        if (drag.pan) this.pan(dx, dy);
        else { o.theta += dx * 0.005; o.phi = Math.min(1.45, Math.max(0.12, o.phi - dy * 0.005)); }
        drag.x = e.clientX; drag.y = e.clientY; o.goal = null; this.wake();
        return;
      }
      const p = this.pick(e.clientX, e.clientY);
      if (p !== this.hovered) { this.hovered = p; this.wake(); }
      onHover(p, e.clientX, e.clientY);
    });
    c.addEventListener('pointerleave', () => { this.hovered = null; onHover(null); this.wake(); });
    c.addEventListener('wheel', (e) => {
      e.preventDefault();
      this.zoom(Math.exp(e.deltaY * 0.001));
    }, { passive: false });
    c.addEventListener('dblclick', () => this.fit());
  }

  // Keyboard: arrows turn and tilt, shift+arrows pan, +/- zoom.
  key(e) {
    const o = this.orbit, step = 0.12;
    const k = e.key;
    if (e.shiftKey && k.startsWith('Arrow')) {
      const s = 40;
      this.pan(k === 'ArrowLeft' ? s : k === 'ArrowRight' ? -s : 0, k === 'ArrowUp' ? s : k === 'ArrowDown' ? -s : 0);
    } else if (k === 'ArrowLeft') o.theta -= step;
    else if (k === 'ArrowRight') o.theta += step;
    else if (k === 'ArrowUp') o.phi = Math.max(0.12, o.phi - step);
    else if (k === 'ArrowDown') o.phi = Math.min(1.45, o.phi + step);
    else if (k === '+' || k === '=') this.zoom(0.85);
    else if (k === '-' || k === '_') this.zoom(1 / 0.85);
    else return false;
    o.goal = null;
    this.wake();
    return true;
  }

  zoom(f) { this.orbit.dist = Math.min(900, Math.max(8, this.orbit.dist * f)); this.wake(); }

  pan(dx, dy) {
    const o = this.orbit, s = o.dist * 0.0016;
    const rx = Math.sin(o.theta), rz = -Math.cos(o.theta);     // screen right, on the floor
    const fx = -Math.cos(o.theta), fz = -Math.sin(o.theta);    // away from the camera, on the floor
    o.tx -= rx * dx * s - fx * dy * s; o.tz -= rz * dx * s - fz * dy * s;
    o.goal = null;
  }

  pick(x, y) {
    if (!this.items.length) return null;
    const r = this.canvas.getBoundingClientRect();
    this.ndc.set(((x - r.left) / r.width) * 2 - 1, -((y - r.top) / r.height) * 2 + 1);
    this.ray.setFromCamera(this.ndc, this.camera);
    const hits = this.ray.intersectObject(this.cubes, false);
    for (const h of hits) {
      const it = h.instanceId != null ? this.items[h.instanceId] : null;
      if (it && it.kind === 'proc') return it.p;
    }
    return null;
  }

  // A metadata-only snapshot for capture and measurement (#debug).
  measure() {
    const info = this.renderer.info;
    return { calls: info.render.calls, triangles: info.render.triangles, instances: this.items.length,
      geometries: info.memory.geometries, frameMs: this.stats.ms, frames: this.stats.frames };
  }
}

const easeOut = (u) => 1 - (1 - Math.min(1, Math.max(0, u))) ** 3;

export const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
