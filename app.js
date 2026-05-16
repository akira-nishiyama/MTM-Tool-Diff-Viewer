const state = {
  base: null,
  target: null,
  diffs: [],
  selected: null,
  filter: "all",
  query: ""
};

const els = {
  baseFile: document.querySelector("#baseFile"),
  targetFile: document.querySelector("#targetFile"),
  baseName: document.querySelector("#baseName"),
  targetName: document.querySelector("#targetName"),
  baseDrop: document.querySelector("#baseDrop"),
  targetDrop: document.querySelector("#targetDrop"),
  diffList: document.querySelector("#diffList"),
  listMeta: document.querySelector("#listMeta"),
  emptyState: document.querySelector("#emptyState"),
  detailsEmpty: document.querySelector("#detailsEmpty"),
  detailsPanel: document.querySelector("#detailsPanel"),
  detailsStatus: document.querySelector("#detailsStatus"),
  detailsTitle: document.querySelector("#detailsTitle"),
  detailsPath: document.querySelector("#detailsPath"),
  propertyDiffs: document.querySelector("#propertyDiffs"),
  propertyRowTemplate: document.querySelector("#propertyRowTemplate"),
  searchInput: document.querySelector("#searchInput"),
  addedCount: document.querySelector("#addedCount"),
  removedCount: document.querySelector("#removedCount"),
  changedCount: document.querySelector("#changedCount"),
  unchangedCount: document.querySelector("#unchangedCount")
};

const textDecoder = new TextDecoder("utf-8");

els.baseFile.addEventListener("change", event => loadFile(event.target.files[0], "base"));
els.targetFile.addEventListener("change", event => loadFile(event.target.files[0], "target"));
els.searchInput.addEventListener("input", event => {
  state.query = event.target.value.trim().toLowerCase();
  renderDiffList();
});

document.querySelectorAll("[data-filter]").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll("[data-filter]").forEach(item => item.classList.remove("active"));
    button.classList.add("active");
    state.filter = button.dataset.filter;
    renderDiffList();
  });
});

setupDropZone(els.baseDrop, "base");
setupDropZone(els.targetDrop, "target");

function setupDropZone(dropZone, side) {
  ["dragenter", "dragover"].forEach(type => {
    dropZone.addEventListener(type, event => {
      event.preventDefault();
      dropZone.classList.add("dragging");
    });
  });

  ["dragleave", "drop"].forEach(type => {
    dropZone.addEventListener(type, event => {
      event.preventDefault();
      dropZone.classList.remove("dragging");
    });
  });

  dropZone.addEventListener("drop", event => {
    const [file] = event.dataTransfer.files;
    if (file) {
      loadFile(file, side);
    }
  });
}

async function loadFile(file, side) {
  if (!file) return;

  const nameEl = side === "base" ? els.baseName : els.targetName;
  nameEl.textContent = `Loading ${file.name}`;

  try {
    const arrayBuffer = await file.arrayBuffer();
    const model = await parseThreatModel(arrayBuffer, file.name);
    state[side] = model;
    nameEl.textContent = file.name;
    computeAndRender();
  } catch (error) {
    console.error(error);
    state[side] = null;
    nameEl.textContent = `Could not read ${file.name}`;
    computeAndRender();
  }
}

async function parseThreatModel(arrayBuffer, fileName) {
  const bytes = new Uint8Array(arrayBuffer);
  const entries = isZip(bytes) ? await readZipEntries(bytes) : [{ name: fileName, bytes }];
  const textEntries = entries
    .filter(entry => isLikelyModelText(entry.name, entry.bytes))
    .map(entry => ({ name: entry.name, text: textDecoder.decode(entry.bytes) }));

  const threatRecords = new Map();
  for (const entry of textEntries) {
    extractThreatRecords(entry.text, entry.name).forEach(record => threatRecords.set(record.id, record));
  }

  if (threatRecords.size > 0) {
    return { fileName, records: threatRecords, kind: "threats" };
  }

  const parsedEntries = entries
    .filter(entry => isLikelyModelText(entry.name, entry.bytes))
    .map(entry => parseEntry(entry))
    .filter(Boolean);

  const records = new Map();
  for (const entry of parsedEntries) {
    collectRecords(entry.value, entry.name, records);
  }

  if (records.size === 0) {
    const fallback = parsedEntries.map(entry => flattenValue(entry.value, entry.name));
    fallback.flat().forEach(item => records.set(item.id, item));
  }

  return { fileName, records };
}

function extractThreatRecords(text, path) {
  const section = firstMatch(text, /<ThreatInstances[\s\S]*?<\/ThreatInstances>/i);
  if (!section) return [];

  return [...section.matchAll(/<a:KeyValueOfstringThreat[\s\S]*?<\/a:KeyValueOfstringThreat[^>]*>/gi)]
    .map((match, index) => buildThreatRecord(match[0], path, index))
    .filter(Boolean);
}

function buildThreatRecord(xml, path, index) {
  const id = xmlValue(xml, "Id");
  if (!id) return null;

  const properties = {
    "Threat ID": id,
    "Type ID": xmlValue(xml, "TypeId"),
    "Title": propertyValue(xml, "Title") || xmlValue(xml, "Title"),
    "Category": propertyValue(xml, "UserThreatCategory") || xmlValue(xml, "UserThreatCategory"),
    "State": xmlValue(xml, "State"),
    "Justification": propertyValue(xml, "Justification") || propertyValue(xml, "StateInformation") || xmlValue(xml, "StateInformation"),
    "Priority": propertyValue(xml, "Priority") || xmlValue(xml, "Priority"),
    "Interaction": propertyValue(xml, "InteractionString") || xmlValue(xml, "InteractionString"),
    "Description": propertyValue(xml, "UserThreatDescription") || xmlValue(xml, "UserThreatDescription"),
    "Short Description": propertyValue(xml, "UserThreatShortDescription") || xmlValue(xml, "UserThreatShortDescription"),
    "Source GUID": xmlValue(xml, "SourceGuid"),
    "Flow GUID": xmlValue(xml, "FlowGuid"),
    "Target GUID": xmlValue(xml, "TargetGuid"),
    "Drawing Surface GUID": xmlValue(xml, "DrawingSurfaceGuid")
  };

  Object.keys(properties).forEach(key => {
    properties[key] = normalizeText(properties[key]);
  });

  const title = properties.Title || `Threat ${id}`;
  const category = properties.Category ? `${properties.Category} threat` : "Threat";

  return {
    id: `Threat:${id}`,
    type: category,
    name: title,
    path: `${path}#ThreatInstances[${index}]`,
    properties
  };
}

function xmlValue(xml, tagName) {
  return firstMatch(xml, new RegExp(`<[a-zA-Z]+:${tagName}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/[a-zA-Z]+:${tagName}>`, "i"));
}

function propertyValue(xml, propertyName) {
  return firstMatch(xml, new RegExp(`<a:Key>${escapeRegExp(propertyName)}<\\/a:Key><a:Value(?:\\s[^>]*)?>([\\s\\S]*?)<\\/a:Value>`, "i"));
}

function firstMatch(text, pattern) {
  const match = text.match(pattern);
  return match ? match[1] || match[0] : "";
}

function normalizeText(value) {
  return decodeXmlEntities(String(value || "").replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim());
}

function decodeXmlEntities(value) {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function isZip(bytes) {
  return bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

async function readZipEntries(bytes) {
  const centralEntries = readCentralDirectory(bytes);
  if (centralEntries.length) {
    return inflateEntries(centralEntries);
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const entries = [];
  let offset = 0;

  while (offset + 30 < bytes.length) {
    const signature = view.getUint32(offset, true);
    if (signature !== 0x04034b50) break;

    const compression = view.getUint16(offset + 8, true);
    const compressedSize = view.getUint32(offset + 18, true);
    const uncompressedSize = view.getUint32(offset + 22, true);
    const nameLength = view.getUint16(offset + 26, true);
    const extraLength = view.getUint16(offset + 28, true);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const dataEnd = dataStart + compressedSize;
    const name = textDecoder.decode(bytes.slice(nameStart, nameStart + nameLength));
    const compressed = bytes.slice(dataStart, dataEnd);

    let entryBytes = null;
    if (compression === 0) {
      entryBytes = compressed;
    } else if (compression === 8 && "DecompressionStream" in window) {
      entryBytes = null;
      entries.push({ name, compressed, compression, uncompressedSize });
    }

    if (entryBytes) entries.push({ name, bytes: entryBytes, uncompressedSize });
    offset = dataEnd;
  }

  return inflateEntries(entries);
}

function readCentralDirectory(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocdOffset = findEndOfCentralDirectory(view);
  if (eocdOffset < 0) return [];

  const entryCount = view.getUint16(eocdOffset + 10, true);
  let offset = view.getUint32(eocdOffset + 16, true);
  const entries = [];

  for (let index = 0; index < entryCount && offset + 46 < bytes.length; index += 1) {
    if (view.getUint32(offset, true) !== 0x02014b50) break;

    const compression = view.getUint16(offset + 10, true);
    const compressedSize = view.getUint32(offset + 20, true);
    const uncompressedSize = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const localHeaderOffset = view.getUint32(offset + 42, true);
    const nameStart = offset + 46;
    const name = textDecoder.decode(bytes.slice(nameStart, nameStart + nameLength));

    const localNameLength = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLength = view.getUint16(localHeaderOffset + 28, true);
    const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
    const compressed = bytes.slice(dataStart, dataStart + compressedSize);

    if (compression === 0) {
      entries.push({ name, bytes: compressed, uncompressedSize });
    } else if (compression === 8 && "DecompressionStream" in window) {
      entries.push({ name, compressed, compression, uncompressedSize });
    }

    offset += 46 + nameLength + extraLength + commentLength;
  }

  return entries;
}

function findEndOfCentralDirectory(view) {
  const minOffset = Math.max(0, view.byteLength - 65557);
  for (let offset = view.byteLength - 22; offset >= minOffset; offset -= 1) {
    if (view.getUint32(offset, true) === 0x06054b50) return offset;
  }
  return -1;
}

function inflateEntries(entries) {
  return Promise.all(entries.map(entry => {
    if (!entry.compressed) return entry;
    return inflateDeflate(entry.compressed).then(bytes => ({ name: entry.name, bytes }));
  }));
}

async function inflateDeflate(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function isLikelyModelText(name, bytes) {
  const lower = name.toLowerCase();
  if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")) return false;
  if (lower.endsWith(".rels") || lower.includes("/_rels/")) return false;
  const sample = textDecoder.decode(bytes.slice(0, Math.min(bytes.length, 256))).trim();
  return sample.startsWith("{") || sample.startsWith("[") || sample.startsWith("<");
}

function parseEntry(entry) {
  const text = textDecoder.decode(entry.bytes);
  const trimmed = text.trim();

  try {
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      return { name: entry.name, value: JSON.parse(trimmed) };
    }
    if (trimmed.startsWith("<")) {
      return { name: entry.name, value: xmlToObject(new DOMParser().parseFromString(trimmed, "application/xml")) };
    }
  } catch (error) {
    console.warn(`Skipping ${entry.name}`, error);
  }

  return null;
}

function xmlToObject(node) {
  if (node.nodeType === Node.DOCUMENT_NODE) {
    return xmlToObject(node.documentElement);
  }

  const obj = { type: node.nodeName };
  if (node.attributes?.length) {
    obj.attributes = {};
    [...node.attributes].forEach(attr => {
      obj.attributes[attr.name] = attr.value;
    });
  }

  const elementChildren = [...node.childNodes].filter(child => child.nodeType === Node.ELEMENT_NODE);
  const text = [...node.childNodes]
    .filter(child => child.nodeType === Node.TEXT_NODE)
    .map(child => child.textContent.trim())
    .filter(Boolean)
    .join(" ");

  if (text) obj.text = text;
  if (elementChildren.length) obj.children = elementChildren.map(xmlToObject);
  return obj;
}

function collectRecords(value, path, records) {
  if (!value || typeof value !== "object") return;

  if (Array.isArray(value)) {
    value.forEach((item, index) => collectRecords(item, `${path}[${index}]`, records));
    return;
  }

  const id = pickId(value);
  const type = pickType(value);
  const name = pickName(value);
  const hasMeaningfulIdentity = id || name || typeMatchesModelObject(type);

  if (hasMeaningfulIdentity) {
    const recordId = `${type || "Object"}:${id || name || path}`;
    records.set(recordId, {
      id: recordId,
      type: type || "Object",
      name: name || id || path,
      path,
      properties: normalizeProperties(value)
    });
  }

  Object.entries(value).forEach(([key, child]) => {
    if (key === "attributes") return;
    collectRecords(child, `${path}.${key}`, records);
  });
}

function pickId(value) {
  const attrs = value.attributes || {};
  return value.id || value.Id || value.ID || value.guid || value.Guid || value.GUID ||
    value.key || value.Key || attrs.id || attrs.Id || attrs.guid || attrs.Guid || null;
}

function pickName(value) {
  const attrs = value.attributes || {};
  return value.name || value.Name || value.title || value.Title || value.displayName ||
    value.DisplayName || attrs.name || attrs.Name || attrs.title || attrs.Title || null;
}

function pickType(value) {
  const attrs = value.attributes || {};
  return value.type || value.Type || value.$type || value.kind || value.Kind ||
    value.nodeType || value.NodeType || attrs.type || attrs.Type || value.type?.name ||
    value.typeName || value.TypeName || value.type || null;
}

function typeMatchesModelObject(type) {
  if (!type) return false;
  return /threat|entity|flow|boundary|element|connector|interaction|mitigation|assumption/i.test(String(type));
}

function normalizeProperties(value) {
  const properties = {};
  Object.entries(value).forEach(([key, child]) => {
    if (key === "children") return;
    properties[key] = stableStringify(child);
  });
  return properties;
}

function flattenValue(value, path) {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap((item, index) => flattenValue(item, `${path}[${index}]`));
  const self = {
    id: `Object:${path}`,
    type: "Object",
    name: path,
    path,
    properties: normalizeProperties(value)
  };
  return [self, ...Object.entries(value).flatMap(([key, child]) => flattenValue(child, `${path}.${key}`))];
}

function stableStringify(value) {
  if (value === null || value === undefined) return "";
  if (typeof value !== "object") return String(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(", ")}]`;
  return JSON.stringify(sortObject(value), null, 2);
}

function sortObject(value) {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!value || typeof value !== "object") return value;
  return Object.keys(value).sort().reduce((result, key) => {
    result[key] = sortObject(value[key]);
    return result;
  }, {});
}

function computeAndRender() {
  if (!state.base || !state.target) {
    state.diffs = [];
    state.selected = null;
    updateCounts();
    renderDiffList();
    renderDetails(null);
    return;
  }

  state.diffs = diffRecords(state.base.records, state.target.records);
  state.selected = state.diffs[0] || null;
  updateCounts();
  renderDiffList();
  renderDetails(state.selected);
}

function diffRecords(baseRecords, targetRecords) {
  const ids = new Set([...baseRecords.keys(), ...targetRecords.keys()]);
  return [...ids].sort(compareRecordIds).flatMap(id => {
    const before = baseRecords.get(id);
    const after = targetRecords.get(id);
    if (!before) return [{ id, status: "added", before: null, after, propertyDiffs: addedProperties(after) }];
    if (!after) return [{ id, status: "removed", before, after: null, propertyDiffs: removedProperties(before) }];

    const propertyDiffs = diffProperties(before.properties, after.properties);
    if (propertyDiffs.length) {
      return [{ id, status: "changed", before, after, propertyDiffs }];
    }
    return [{ id, status: "unchanged", before, after, propertyDiffs: unchangedProperties(after) }];
  });
}

function compareRecordIds(left, right) {
  const leftNumber = numericId(left);
  const rightNumber = numericId(right);
  if (leftNumber !== null && rightNumber !== null && leftNumber !== rightNumber) {
    return leftNumber - rightNumber;
  }
  if (leftNumber !== null && rightNumber === null) return -1;
  if (leftNumber === null && rightNumber !== null) return 1;
  return left.localeCompare(right, undefined, { numeric: true, sensitivity: "base" });
}

function numericId(id) {
  const value = String(id).replace(/^Threat:/, "");
  return /^\d+$/.test(value) ? Number(value) : null;
}

function diffProperties(before = {}, after = {}) {
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  return [...keys].sort().flatMap(key => {
    const oldValue = before[key] ?? "";
    const newValue = after[key] ?? "";
    return oldValue === newValue ? [] : [{ key, before: oldValue, after: newValue }];
  });
}

function addedProperties(record) {
  return Object.entries(record.properties).map(([key, after]) => ({ key, before: "", after }));
}

function removedProperties(record) {
  return Object.entries(record.properties).map(([key, before]) => ({ key, before, after: "" }));
}

function unchangedProperties(record) {
  return Object.entries(record.properties).map(([key, value]) => ({ key, before: value, after: value }));
}

function updateCounts() {
  els.addedCount.textContent = state.diffs.filter(diff => diff.status === "added").length;
  els.removedCount.textContent = state.diffs.filter(diff => diff.status === "removed").length;
  els.changedCount.textContent = state.diffs.filter(diff => diff.status === "changed").length;
  els.unchangedCount.textContent = state.diffs.filter(diff => diff.status === "unchanged").length;
}

function renderDiffList() {
  const diffs = visibleDiffs();
  if (diffs.length && !diffs.some(diff => diff.id === state.selected?.id)) {
    state.selected = diffs[0];
    renderDetails(state.selected);
  } else if (!diffs.length && state.selected) {
    state.selected = null;
    renderDetails(null);
  }

  els.diffList.replaceChildren();
  els.emptyState.hidden = Boolean(diffs.length);
  els.listMeta.textContent = `${diffs.length} ${diffs.length === 1 ? "threat" : "threats"} shown`;

  diffs.forEach(diff => {
    const record = diff.after || diff.before;
    const item = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = `diff-item ${state.selected?.id === diff.id ? "active" : ""}`;
    button.innerHTML = `
      <span class="badge ${diff.status}">${diff.status}</span>
      <strong></strong>
      <span></span>
    `;
    button.querySelector("strong").textContent = record.name;
    button.querySelector("span:last-child").textContent = `${record.id.replace("Threat:", "ID ")} - ${record.type}`;
    button.addEventListener("click", () => {
      state.selected = diff;
      renderDiffList();
      renderDetails(diff);
    });
    item.append(button);
    els.diffList.append(item);
  });
}

function visibleDiffs() {
  return state.diffs.filter(diff => {
    if (state.filter !== "all" && diff.status !== state.filter) return false;
    if (!state.query) return true;
    const record = diff.after || diff.before;
    const haystack = [
      diff.status,
      record.id,
      record.type,
      record.name,
      record.path,
      ...diff.propertyDiffs.flatMap(item => [item.key, item.before, item.after])
    ].join("\n").toLowerCase();
    return haystack.includes(state.query);
  });
}

function renderDetails(diff) {
  els.detailsEmpty.hidden = Boolean(diff);
  els.detailsPanel.hidden = !diff;
  els.propertyDiffs.replaceChildren();
  if (!diff) return;

  const record = diff.after || diff.before;
  els.detailsStatus.textContent = diff.status;
  els.detailsStatus.className = `status-pill ${diff.status}`;
  els.detailsTitle.textContent = record.name;
  els.detailsPath.textContent = `${record.id.replace("Threat:", "Threat ID ")} - ${record.type}`;

  diff.propertyDiffs.forEach(property => {
    const row = els.propertyRowTemplate.content.firstElementChild.cloneNode(true);
    row.querySelector(".property-key").textContent = property.key;
    renderValueDiff(row.querySelector(".before"), property.before, property.after);
    renderValueDiff(row.querySelector(".after"), property.after, property.before);
    els.propertyDiffs.append(row);
  });
}

function renderValueDiff(element, value, comparisonValue) {
  element.replaceChildren();
  const text = value || "";
  if (!text) {
    element.textContent = " ";
    return;
  }

  const comparisonText = comparisonValue || "";
  if (text === comparisonText) {
    element.textContent = text;
    return;
  }

  getChangedTokenRuns(text, comparisonText).forEach(run => {
    const node = document.createTextNode(run.text);
    if (!run.changed) {
      element.append(node);
      return;
    }

    const highlight = document.createElement("span");
    highlight.className = "diff-highlight";
    highlight.append(node);
    element.append(highlight);
  });
}

function getChangedTokenRuns(text, comparisonText) {
  const tokens = tokenizeForDiff(text);
  const comparisonTokens = tokenizeForDiff(comparisonText);
  if (!tokens.length) return [];

  const unchanged = findUnchangedTokenIndexes(tokens, comparisonTokens);
  const runs = [];
  tokens.forEach((token, index) => {
    const changed = !unchanged.has(index);
    const last = runs[runs.length - 1];
    if (last && last.changed === changed) {
      last.text += token;
    } else {
      runs.push({ text: token, changed });
    }
  });
  return runs;
}

function tokenizeForDiff(text) {
  return String(text).match(/\s+|[A-Za-z0-9_:-]+|[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]|[^\sA-Za-z0-9_:-]/gu) || [];
}

function findUnchangedTokenIndexes(tokens, comparisonTokens) {
  if (!comparisonTokens.length) return new Set();
  const cellCount = tokens.length * comparisonTokens.length;
  if (cellCount > 40000) {
    return findUnchangedTokenIndexesByEdges(tokens, comparisonTokens);
  }

  const rows = tokens.length + 1;
  const cols = comparisonTokens.length + 1;
  const table = Array.from({ length: rows }, () => Array(cols).fill(0));

  for (let row = tokens.length - 1; row >= 0; row -= 1) {
    for (let col = comparisonTokens.length - 1; col >= 0; col -= 1) {
      table[row][col] = tokens[row] === comparisonTokens[col]
        ? table[row + 1][col + 1] + 1
        : Math.max(table[row + 1][col], table[row][col + 1]);
    }
  }

  const unchanged = new Set();
  let row = 0;
  let col = 0;
  while (row < tokens.length && col < comparisonTokens.length) {
    if (tokens[row] === comparisonTokens[col]) {
      unchanged.add(row);
      row += 1;
      col += 1;
    } else if (table[row + 1][col] >= table[row][col + 1]) {
      row += 1;
    } else {
      col += 1;
    }
  }
  return unchanged;
}

function findUnchangedTokenIndexesByEdges(tokens, comparisonTokens) {
  const unchanged = new Set();
  let start = 0;
  while (
    start < tokens.length &&
    start < comparisonTokens.length &&
    tokens[start] === comparisonTokens[start]
  ) {
    unchanged.add(start);
    start += 1;
  }

  let end = 0;
  while (
    end < tokens.length - start &&
    end < comparisonTokens.length - start &&
    tokens[tokens.length - 1 - end] === comparisonTokens[comparisonTokens.length - 1 - end]
  ) {
    unchanged.add(tokens.length - 1 - end);
    end += 1;
  }
  return unchanged;
}
