const $ = s => document.querySelector(s);
// brand:begin -- identical in every page; tests/test_ui_brand.py keeps the copies equal.
// The product is ARGUS-INSTINCT. Server text can still say JARVIS (finding titles keep their
// identity for acknowledgements and history), so it is re-branded at display time.
// Real Windows objects keep their spelling so they can be found in Task Scheduler
// and Services; lowercase commands (jarvis ..., jarvis.service) are never touched.
// Idempotent: a name already followed by -1 is left alone, so text that went
// through the rule twice, or a build that renames JARVIS to ARGUS, never reads ARGUS-INSTINCT-1.
const BRAND = "ARGUS-INSTINCT";
const BRAND_KEEP = /^ (input hook|independent health monitor|connectivity guard|native sensor|Jarvis)/;
const brand = (s) => String(s ?? "").replace(/\bJARVIS\b(?!-(?:1|INSTINCT)\b)/g,
  (m, i, all) => (BRAND_KEEP.test(all.slice(i + m.length)) ? m : BRAND));
// brand:end
const esc = s => brand(s).replace(/[&<>]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
const attr = s => esc(s).replace(/"/g,"&quot;");
const cls = sev => ({ok:"ok",low:"low",medium:"high",high:"high",critical:"crit"}[sev]||"dim");

function yesterday(){ const d=new Date(Date.now()-864e5); return d.toISOString().slice(0,10); }

let viewer=null, marker=null;
function initGlobe(img){
  if(typeof Cesium==="undefined"){ $("#fallback").style.display="flex"; return; }
  try{
    try{ Cesium.Ion.defaultAccessToken = undefined; }catch(e){}
    viewer = new Cesium.Viewer("globe", {
      baseLayerPicker:false, geocoder:false, timeline:false, animation:false,
      homeButton:false, sceneModePicker:false, navigationHelpButton:false,
      fullscreenButton:false, infoBox:false, selectionIndicator:false,
      baseLayer:false, requestRenderMode:true
    });
    const provider = new Cesium.WebMapTileServiceImageryProvider({
      url: img.endpoint + "?TIME=" + yesterday(),
      layer: img.layer, style:"default", format: img.format,
      tileMatrixSetID: img.tile_matrix_set, maximumLevel: img.max_level,
      tilingScheme: new Cesium.WebMercatorTilingScheme(),
      tileWidth:256, tileHeight:256, credit: img.attribution
    });
    // Static seamless Earth underneath: covers daily-tile errors and poles.
    // (Daily true-color tiles are JPEG — no alpha — so this is a fallback
    // for missing tiles, not transparency through no-data pixels.)
    if(img.base){
      const base = new Cesium.WebMapTileServiceImageryProvider({
        url: img.base.endpoint,
        layer: img.base.layer, style:"default", format: img.base.format,
        tileMatrixSetID: img.base.tile_matrix_set, maximumLevel: img.base.max_level,
        tilingScheme: new Cesium.WebMercatorTilingScheme(),
        tileWidth:256, tileHeight:256, credit: img.base.attribution
      });
      viewer.imageryLayers.addImageryProvider(base);
    }
    viewer.imageryLayers.addImageryProvider(provider);
    // Mid bands: 10 m Sentinel-2 mosaic (z8–z13) sharpens the regional
    // view where the daily layer runs out of pixels.
    if(img.mid){
      const mid = new Cesium.UrlTemplateImageryProvider({
        url: img.mid.url_template,
        // A global imagery provider must start at level zero.  Giving it a
        // global minimumLevel of 8 asks Cesium to enumerate 65k root tiles
        // and can halt rendering with "Too many properties to enumerate".
        maximumLevel: img.mid.max_level,
        tilingScheme: new Cesium.WebMercatorTilingScheme(),
        tileWidth:256, tileHeight:256, credit: img.mid.attribution
      });
      const midLayer = new Cesium.ImageryLayer(mid, {
        minimumTerrainLevel: img.mid.min_level,
        maximumTerrainLevel: img.mid.max_level
      });
      viewer.imageryLayers.add(midLayer);
    }
    // Street detail at close zoom (z14–z19): sub-metre imagery takes over
    // when the camera dives in.
    if(img.detail){
      const detail = new Cesium.UrlTemplateImageryProvider({
        url: img.detail.url_template,
        maximumLevel: img.detail.max_level,
        tilingScheme: new Cesium.WebMercatorTilingScheme(),
        tileWidth:256, tileHeight:256, credit: img.detail.attribution
      });
      const detailLayer = new Cesium.ImageryLayer(detail, {
        minimumTerrainLevel: img.detail.min_level,
        maximumTerrainLevel: img.detail.max_level
      });
      viewer.imageryLayers.add(detailLayer);
    }
    viewer.scene.globe.baseColor = Cesium.Color.fromCssColorString("#05070d");
  }catch(e){ console.error(e); $("#globe").style.display="none"; $("#fallback").style.display="flex"; }
}

/* Accuracy-aware camera: street scale for tight fixes, city scale for
   loose ones, global context when there is no position. Pure. */
function viewHeight(view){
  const mode = (view||{}).mode;
  if(mode==="street") return 1500;
  if(mode==="city") return 60000;
  return 2.2e6;
}

// -- 2D local security map (Leaflet) -----------------------------------------
// The globe stays for global context; street-level work happens here:
// named streets, accurate zoom, trusted-zone editing, scale, return-to-me.
// Tile failures degrade to a notice — never a silent empty pane.
let map2d=null, layers2d={}, marker2d=null, pin2d=null, zones2d=[],
    mode="globe", lastPayload=null, map2dCentered=false, tileErrs=0;

function setMode(m){
  mode = (m==="satellite"||m==="hybrid"||m==="street") ? m : "globe";
  document.querySelectorAll("#modebar button").forEach(b=>
    b.classList.toggle("on", b.dataset.mode===mode));
  const two = mode!=="globe";
  $("#map2d").style.display = two ? "block" : "";
  $("#globe").style.display = two ? "none" : "";
  $("#mebtn").style.display = two ? "block" : "none";
  if(two && lastPayload) sync2d(lastPayload, true);
  if(map2d) map2d.invalidateSize();
}

function init2d(payload){
  if(map2d) return true;
  if(typeof L==="undefined"){
    $("#map2dfallback").style.display="flex"; return false;
  }
  const v = payload.view||{};
  const c = (payload.imagery||{}).center;
  const lat = c ? c.lat : 0, lon = c ? c.lon : 0;
  const zoom = c ? (v.zoom!=null ? v.zoom : 14) : 2;
  layers2d = {
    street: L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png",
      { maxZoom:19, attribution:"© OpenStreetMap contributors" }),
    satellite: L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
      { maxZoom:19, attribution:"Esri World Imagery" }),
    hybrid: L.layerGroup([
      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
        { maxZoom:19 }),
      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}",
        { maxZoom:19, attribution:"Esri Reference" }) ])
  };
  Object.values(layers2d).forEach(l=>{
    l.on("tileerror", ()=>{
      if(++tileErrs===6) $("#tilewarn").textContent =
        "map tiles are failing to load (offline or provider down?) — status panel and globe still work.";
      $("#tilewarn").style.display="block";
    });
    l.on("load", ()=>{ tileErrs=0; $("#tilewarn").style.display="none"; });
  });
  map2d = L.map("map2d", { zoomControl:true }).setView([lat, lon], zoom);
  map2d.addControl(L.control.scale({ imperial:false }));
  layers2d.street.addTo(map2d);
  map2d.on("click", e=>stage(e.latlng.lat, e.latlng.lng, "pin"));
  map2dCentered = !!c;
  sync2d(payload, false);
  return true;
}

function sync2d(payload, recenter){
  lastPayload = payload;
  if(!map2d) return;
  const want = layers2d[mode] || layers2d.street;
  Object.entries(layers2d).forEach(([name, layer])=>{
    if(layer===want){ if(!map2d.hasLayer(layer)) layer.addTo(map2d); }
    else if(map2d.hasLayer(layer)) map2d.removeLayer(layer);
  });
  if(marker2d){ map2d.removeLayer(marker2d); marker2d=null; }
  zones2d.forEach(l=>map2d.removeLayer(l)); zones2d=[];
  (payload.zones||[]).forEach(z=>{
    zones2d.push(L.circle([z.lat, z.lon], { radius:z.radius_m, color:"#39d98a",
      weight:1, fillOpacity:.15 }).addTo(map2d).bindTooltip(esc(z.name)));
  });
  const c = (payload.imagery||{}).center;
  if(c){
    marker2d = L.circleMarker([c.lat, c.lon], { radius:7, color:"#fff",
      weight:2, fillColor:"#7db4ff", fillOpacity:1 }).addTo(map2d)
      .bindTooltip(c.source==="user-set" ? "you (set manually)" : "this device");
    if(recenter || !map2dCentered){
      map2d.setView([c.lat, c.lon], (payload.view||{}).zoom!=null ? payload.view.zoom : 14);
      map2dCentered = true;
    }
  }
  if(pin2d){ map2d.removeLayer(pin2d); pin2d=null; }
  if(pending && pending.lat!=null){
    pin2d = L.circleMarker([pending.lat, pending.lon], { radius:7, color:"#fff",
      weight:2, fillColor:"#ffb347", fillOpacity:1 }).addTo(map2d);
  }
}

function returnToMe(){
  const c = lastPayload && (lastPayload.imagery||{}).center;
  if(c && map2d) map2d.setView([c.lat, c.lon],
    ((lastPayload||{}).view||{}).zoom!=null ? lastPayload.view.zoom : 14);
}

function place(payload){
  lastPayload = payload;
  if(map2d && mode!=="globe") sync2d(payload, false);
  if(!viewer) return;
  viewer.entities.removeAll(); pin=null;
  const img = payload.imagery, c = img.center, h = viewHeight(payload.view);
  // Trusted zones as circles.
  (payload.zones||[]).forEach(z=>{
    viewer.entities.add({ name:z.name,
      position: Cesium.Cartesian3.fromDegrees(z.lon, z.lat),
      ellipse:{ semiMajorAxis:z.radius_m, semiMinorAxis:z.radius_m,
        material: Cesium.Color.fromCssColorString("#39d98a").withAlpha(.18),
        outline:true, outlineColor: Cesium.Color.fromCssColorString("#39d98a") },
      label:{ text:z.name, font:"12px monospace", fillColor:Cesium.Color.WHITE,
        pixelOffset:new Cesium.Cartesian2(0,-18), showBackground:true,
        backgroundColor: Cesium.Color.fromCssColorString("#0a1424").withAlpha(.8) } });
  });
  if(c){
    const label = c.source==="device fix" ? "this device"
                : c.source==="user-set" ? "you (set manually)" : "home zone";
    const col = c.source==="home zone" ? "#6f89b3" : "#7db4ff";
    viewer.entities.add({
      position: Cesium.Cartesian3.fromDegrees(c.lon, c.lat),
      point:{ pixelSize:12, color: Cesium.Color.fromCssColorString(col),
        outlineColor: Cesium.Color.WHITE, outlineWidth:2 },
      label:{ text: label, font:"12px monospace",
        fillColor: Cesium.Color.fromCssColorString(col),
        pixelOffset:new Cesium.Cartesian2(0,18) } });
    viewer.camera.flyTo({ destination: Cesium.Cartesian3.fromDegrees(c.lon, c.lat, h), duration:2 });
  }
}

// -- letting the user set their own location --------------------------------
let pending=null, pin=null;
function stage(lat, lon, label){
  pending={lat, lon, label};
  $("#geohint").innerHTML = `<span class="low">${esc(label||"")}</span> ${lat.toFixed(4)}, ${lon.toFixed(4)} — confirm below.`;
  $("#confirm").style.display="block";
  if(map2d && mode!=="globe"){
    map2d.setView([lat, lon], Math.max(map2d.getZoom(), 14));
    if(pin2d) map2d.removeLayer(pin2d);
    pin2d = L.circleMarker([lat, lon], { radius:7, color:"#fff",
      weight:2, fillColor:"#ffb347", fillOpacity:1 }).addTo(map2d);
  }
  if(viewer){
    if(pin) viewer.entities.remove(pin);
    pin = viewer.entities.add({ position: Cesium.Cartesian3.fromDegrees(lon, lat),
      point:{ pixelSize:12, color: Cesium.Color.fromCssColorString("#ffb347"),
        outlineColor: Cesium.Color.WHITE, outlineWidth:2 } });
    viewer.camera.flyTo({ destination: Cesium.Cartesian3.fromDegrees(lon, lat, 1.2e6), duration:1.4 });
    viewer.scene.requestRender();
  }
}
function wireControls(){
  $("#findbtn").onclick = ()=>{
    const q = $("#place").value.trim(); if(!q) return;
    $("#geohint").textContent = "searching OpenStreetMap…";
    fetch("https://nominatim.openstreetmap.org/search?format=json&limit=1&q="+encodeURIComponent(q),
      { headers:{ "Accept":"application/json" } })
      .then(r=>r.json()).then(a=>{
        if(!a.length){ $("#geohint").textContent = "no match — try a fuller name, or click the map."; return; }
        stage(parseFloat(a[0].lat), parseFloat(a[0].lon), a[0].display_name.split(",").slice(0,2).join(",")||q);
      }).catch(()=>{ $("#geohint").textContent = "lookup failed (offline?) — click the map to drop a pin instead."; });
  };
  $("#place").addEventListener("keydown", e=>{ if(e.key==="Enter"){ e.preventDefault(); $("#findbtn").click(); }});
  $("#setbtn").onclick = ()=>{
    if(!pending) return;
    fetch("/api/geo/here", { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify(pending) }).then(r=>r.json()).then(()=>refresh()).catch(()=>{});
  };
  $("#clearbtn").onclick = ()=>{
    fetch("/api/geo/here", { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({clear:true}) }).then(()=>refresh()).catch(()=>{});
  };
  if(viewer){
    const handler = new Cesium.ScreenSpaceEventHandler(viewer.scene.canvas);
    handler.setInputAction(evt=>{
      const cart = viewer.camera.pickEllipsoid(evt.position, viewer.scene.globe.ellipsoid);
      if(!cart) return;
      const carto = Cesium.Cartographic.fromCartesian(cart);
      stage(Cesium.Math.toDegrees(carto.latitude), Cesium.Math.toDegrees(carto.longitude), "pin");
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
  }
  document.querySelectorAll("#modebar button").forEach(b=>{
    b.onclick = ()=>{
      if(b.dataset.mode==="globe"){ setMode("globe"); return; }
      if(init2d(lastPayload||{imagery:{},view:{zoom:14}})) setMode(b.dataset.mode);
    };
  });
  $("#mebtn").onclick = returnToMe;
  let zoneKind = "custom";
  const zonePreset = (name, kind, radius)=>{
    $("#zonename").value = name; $("#zoneradius").value = radius; zoneKind = kind;
    $("#zonehint").textContent = pending && pending.lat!=null
      ? `pin ready — save it as ${name}.`
      : `${name} preset filled — drop a pin on the map, then save.`;
  };
  $("#zonehome").onclick = ()=>zonePreset("HOME", "home", 200);
  $("#zonework").onclick = ()=>zonePreset("WORKPLACE", "workplace", 300);
  $("#zonefind").onclick = ()=>{
    const q = $("#zoneaddr").value.trim(); if(!q) return;
    $("#zonehint").textContent = "searching OpenStreetMap…";
    fetch("https://nominatim.openstreetmap.org/search?format=json&limit=1&q="+encodeURIComponent(q),
      { headers:{ "Accept":"application/json" } })
      .then(r=>r.json()).then(a=>{
        if(!a.length){ $("#zonehint").textContent = "no match — try a fuller address, or pin the map."; return; }
        $("#zoneaddr").value = a[0].display_name.split(",").slice(0,3).join(",");
        stage(parseFloat(a[0].lat), parseFloat(a[0].lon), "address");
        $("#zonehint").textContent = "address pinned — name it and save.";
      }).catch(()=>{ $("#zonehint").textContent = "lookup failed (offline?) — pin the map instead."; });
  };
  $("#zoneaddr").addEventListener("keydown", e=>{ if(e.key==="Enter"){ e.preventDefault(); $("#zonefind").click(); }});
  $("#zonesave").onclick = ()=>{
    const name = $("#zonename").value.trim();
    const radius = Math.max(20, Math.min(50000, parseInt($("#zoneradius").value||"200", 10)||200));
    const address = $("#zoneaddr").value.trim();
    if(!name){ $("#zonehint").textContent = "give the zone a name first."; return; }
    if(!pending || pending.lat==null){ $("#zonehint").textContent = "drop a pin first (click the map), then save."; return; }
    fetch("/api/geo/zone", { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ name, lat:pending.lat, lon:pending.lon,
        radius_m:radius, address, kind:zoneKind }) })
      .then(r=>r.json()).then(res=>{
        if(res.ok){ $("#zonehint").textContent = `zone '${name}' saved.`; refresh(); }
        else $("#zonehint").textContent = "not saved: " + (res.error||"unknown");
      }).catch(()=>{ $("#zonehint").textContent = "not saved (request failed)."; });
  };
  $("#zones").addEventListener("click", e=>{
    const btn = e.target.closest("[data-rmzone]");
    if(!btn) return;
    fetch("/api/geo/zone", { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ remove:btn.dataset.rmzone }) })
      .then(r=>r.json()).then(()=>refresh()).catch(()=>{});
  });
  $("#zones").addEventListener("change", e=>{
    const input = e.target.closest(".zrad");
    if(!input) return;
    const row = input.closest("[data-zone]");
    const radius = Math.max(20, Math.min(50000, parseInt(input.value||"0", 10)||0));
    if(!row || !radius){ refresh(); return; }
    fetch("/api/geo/zone", { method:"POST", headers:{ "Content-Type":"application/json" },
      body: JSON.stringify({ name:row.dataset.zone, radius_m:radius }) })
      .then(r=>r.json()).then(res=>{
        if(!res.ok) $("#zonehint").textContent = "radius not saved: " + (res.error||"unknown");
        refresh();
      }).catch(()=>{ $("#zonehint").textContent = "radius not saved (request failed)."; });
  });
}

function render(p){
  $("#ts").textContent = "updated " + new Date().toLocaleTimeString();
  const loc=p.location||{}, conf=p.confidence||{score:0,signals:[]};
  let locHtml;
  if(loc.status==="ok") locHtml = `<div class="row"><span class="k">status</span><span class="v ok">located</span></div>`+
      `<div class="row"><span class="k">zone</span><span class="v">${esc(loc.zone||"—")}</span></div>`+
      `<div class="row"><span class="k">accuracy</span><span class="v">${loc.accuracy_m==null?"n/a — set manually":"~"+Math.round(loc.accuracy_m)+" m"}</span></div>`+
      `<div class="row"><span class="k">source</span><span class="v">${esc(loc.source||"")}</span></div>`;
  else locHtml = `<div class="row"><span class="k">status</span><span class="v ${loc.status==="denied"?"low":"dim"}">${esc(loc.status||"unknown")}</span></div>`+
      `<div class="sig">${esc(loc.reason||"ARGUS-INSTINCT never guesses a position from your IP.")}</div>`;
  $("#loc").innerHTML = locHtml +
    `<div class="row" style="margin-top:6px"><span class="k">confidence</span><span class="v">${Math.round(conf.score*100)}%</span></div>`;
  const v=p.view||{};
  $("#loc").innerHTML += v.mode
    ? `<div class="row"><span class="k">view</span><span class="v">${esc(v.mode)}${v.zoom!=null?" · z"+v.zoom:""}</span></div>`+
      `<div class="sig dim">${esc(v.reason||"")}</div>` : "";
  $("#confbar").style.width = Math.round(conf.score*100)+"%";
  $("#signals").innerHTML = (conf.signals||[]).map(s=>`<div class="sig">• ${esc(s.name)} <span class="dim">(${s.weight})</span></div>`).join("")||`<div class="sig dim">no signals</div>`;

  $("#devices").innerHTML = (p.devices||[]).map(d=>
    `<div class="row"><span class="k">${esc(d.name)} <span class="dim">${esc(d.kind)}</span></span>`+
    `<span class="v ${d.trust==="trusted"?"ok":"high"}">${esc(d.trust)}</span></div>`).join("");

  $("#zones").innerHTML = (p.zones||[]).length ? (p.zones||[]).map(z=>
    `<div class="zrow" data-zone="${attr(z.name)}">`+
    `<span class="k">${esc(z.name)}${z.kind?` <span class="pill dim">${esc(z.kind)}</span>`:""}`+
    `<br><span class="v dim">${z.lat.toFixed(3)}, ${z.lon.toFixed(3)}`+
    `${z.address?` · ${esc(z.address)}`:""}</span></span>`+
    `<span style="white-space:nowrap"><input class="zrad" type="number" min="20" max="50000" `+
    `value="${z.radius_m}" title="radius in metres — edits on change" `+
    `style="width:64px;background:#0a1424;border:1px solid var(--line);color:var(--fg);border-radius:6px;padding:2px 6px;font:inherit"> `+
    `<button class="zbtn" data-rmzone="${attr(z.name)}" title="remove zone">✕</button></span></div>`).join("")
    : `<div class="sig dim">none — drop a pin on the map and save it below,<br>or: jarvis geo zone add HOME LAT LON</div>`;

  $("#anoms").innerHTML = (p.anomalies||[]).length ? (p.anomalies||[]).map(a=>
    `<div class="anom ${cls(a.severity)}"><b class="${cls(a.severity)}">${esc(a.kind)}</b><br>${esc(a.detail)}</div>`).join("")
    : `<div class="sig ok">none</div>`;

  const img=p.imagery||{};
  $("#imagery").innerHTML = `<div class="row"><span class="k">provider</span><span class="v">${esc(img.provider)}</span></div>`+
    `<div class="row"><span class="k">layer</span><span class="v dim">${esc(img.layer)}</span></div>`+
    `<div class="row"><span class="k">observed</span><span class="v dim">${esc(img.date||"—")}</span></div>`+
    `<div class="row"><span class="k">mid</span><span class="v dim">${esc((img.mid||{}).layer||"none")} · z${(img.mid||{}).min_level}–${(img.mid||{}).max_level}</span></div>`+
    `<div class="row"><span class="k">detail</span><span class="v dim">${esc((img.detail||{}).layer||"none")} · z${(img.detail||{}).min_level}–${(img.detail||{}).max_level}</span></div>`+
    `<div class="row"><span class="k">fallback</span><span class="v dim">${esc((img.base||{}).layer||"none")}</span></div>`+
    `<div class="sig">${esc(img.cadence)}</div><div class="sig dim">${esc(img.attribution)}</div>`;
}

let started=false;
function refresh(){
  return fetch("/api/geo").then(r=>r.json()).then(p=>{
    lastPayload = p;
    if(!started){
      initGlobe(p.imagery||{});
      wireControls();
      // Open where the accuracy says something useful: street/city fixes
      // start on the 2D street map, unknown position on the 3D globe.
      const vm = (p.view||{}).mode;
      if((vm==="street"||vm==="city") && init2d(p)) setMode("street");
      else setMode("globe");
      started=true;
    }
    render(p); place(p);
    $("#confirm").style.display="none"; pending=null;
    if(map2d && mode!=="globe" && pin2d){ map2d.removeLayer(pin2d); pin2d=null; }
    $("#geohint").innerHTML="or click the map to drop a pin, then confirm.";
  });
}
refresh().catch(e=>{ $("#fallback").style.display="flex";
  $("#loc").innerHTML=`<div class="sig crit">/api/geo unavailable: ${esc(e)}</div>`; });
setInterval(()=>fetch("/api/geo").then(r=>r.json()).then(render).catch(()=>{}), 30000);
