const sampleLogs = {
  syslog:
    'Jun 04 11:23:45 wazuh-agent sshd[12345]: Failed password for admin from 192.168.1.10 port 55222 ssh2',
  json:
    '2026-06-04T11:23:45Z app-gateway: json_data: {"event":"login_failed","src_ip":"192.168.1.10","username":"admin","status":"failed"}',
};

const state = {
  analysis: null,
};

const elements = {
  decoderName: document.querySelector("#decoder-name"),
  sampleLog: document.querySelector("#sample-log"),
  generate: document.querySelector("#generate"),
  clear: document.querySelector("#clear"),
  sampleSyslog: document.querySelector("#sample-syslog"),
  sampleJson: document.querySelector("#sample-json"),
  summary: document.querySelector("#summary"),
  fieldEditor: document.querySelector("#field-editor"),
  fieldList: document.querySelector("#field-list"),
  xmlOutput: document.querySelector("#xml-output"),
  copyXml: document.querySelector("#copy-xml"),
};

elements.generate.addEventListener("click", handleGenerate);
elements.clear.addEventListener("click", handleClear);
elements.sampleSyslog.addEventListener("click", () => loadSample("syslog"));
elements.sampleJson.addEventListener("click", () => loadSample("json"));
elements.copyXml.addEventListener("click", copyXml);

function handleGenerate() {
  const log = elements.sampleLog.value.trim();
  const preferredName = elements.decoderName.value.trim();

  if (!log) {
    renderEmpty("Paste a log line first.");
    return;
  }

  state.analysis = analyzeLog(log, preferredName);
  renderAnalysis();
}

function handleClear() {
  elements.decoderName.value = "";
  elements.sampleLog.value = "";
  state.analysis = null;
  renderEmpty("Enter a log line to generate a decoder.");
}

function loadSample(kind) {
  elements.sampleLog.value = sampleLogs[kind];
  if (!elements.decoderName.value.trim()) {
    elements.decoderName.value =
      kind === "json" ? "custom_app_json" : "custom_sshd_failure";
  }
  handleGenerate();
}

function copyXml() {
  const xml = elements.xmlOutput.textContent;
  if (!xml) {
    return;
  }

  navigator.clipboard
    .writeText(xml)
    .then(() => {
      const original = elements.copyXml.textContent;
      elements.copyXml.textContent = "Copied";
      window.setTimeout(() => {
        elements.copyXml.textContent = original;
      }, 1600);
    })
    .catch(() => {
      elements.copyXml.textContent = "Copy failed";
      window.setTimeout(() => {
        elements.copyXml.textContent = "Copy XML";
      }, 1600);
    });
}

function renderEmpty(message) {
  elements.summary.textContent = message;
  elements.fieldEditor.hidden = true;
  elements.fieldList.innerHTML = "";
  elements.xmlOutput.textContent = "";
}

function analyzeLog(rawLog, preferredName) {
  const syslog = parseSyslogHeader(rawLog);
  const workingLog = syslog ? syslog.message : rawLog;
  const jsonContext = detectJsonContext(rawLog, workingLog);
  const name =
    sanitizeDecoderName(preferredName) ||
    inferDecoderName(syslog, jsonContext, workingLog);

  if (jsonContext) {
    return buildJsonAnalysis({
      syslog,
      jsonContext,
      name,
    });
  }

  return buildRegexAnalysis({
    rawLog,
    syslog,
    workingLog,
    name,
  });
}

function parseSyslogHeader(log) {
  const patterns = [
    /^(?<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+(?<hostname>[^:\s]+)\s+(?<program>[^\s\[:]+)(?:\[\d+\])?:\s*(?<message>.*)$/u,
    /^(?<timestamp>\d{4}-\d{2}-\d{2}[T ][^ ]+)\s+(?<hostname>[^:\s]+)\s+(?<program>[^\s\[:]+)(?:\[\d+\])?:\s*(?<message>.*)$/u,
    /^(?<timestamp>\d{4}-\d{2}-\d{2}[T ][^ ]+)\s+(?<program>[^\s\[:]+)(?:\[\d+\])?:\s*(?<message>.*)$/u,
    /^(?<timestamp>\d{4}\s+[A-Z][a-z]{2}\s+\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?<program>[^\s\[:]+)(?:\[\d+\])?:\s*(?<message>.*)$/u,
  ];

  for (const pattern of patterns) {
    const match = log.match(pattern);
    if (!match || !match.groups) {
      continue;
    }

    return {
      timestamp: match.groups.timestamp || "",
      hostname: match.groups.hostname || "",
      program: match.groups.program || "",
      message: match.groups.message || "",
    };
  }

  return null;
}

function detectJsonContext(rawLog, workingLog) {
  const fullJson = tryParseJson(rawLog);
  if (fullJson) {
    return {
      json: fullJson,
      target: rawLog,
      prefix: "",
      location: "full",
    };
  }

  const messageJson = tryParseJson(workingLog);
  if (messageJson) {
    return {
      json: messageJson,
      target: workingLog,
      prefix: "",
      location: "message",
    };
  }

  const embedded = detectEmbeddedJson(workingLog);
  if (embedded) {
    return {
      json: embedded.json,
      target: workingLog,
      prefix: embedded.prefix,
      location: "embedded",
    };
  }

  return null;
}

function tryParseJson(text) {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return null;
  }

  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function detectEmbeddedJson(text) {
  const start = text.indexOf("{");
  if (start === -1) {
    return null;
  }

  const prefix = text.slice(0, start);
  const candidate = text.slice(start).trim();
  const parsed = tryParseJson(candidate);
  if (!parsed) {
    return null;
  }

  return { prefix, json: parsed };
}

function buildJsonAnalysis({ syslog, jsonContext, name }) {
  const lines = [`<decoder name="${name}">`];
  const summaryParts = ["Detected JSON log"];
  const suggestions = summarizeJsonKeys(jsonContext.json);

  if (syslog?.program) {
    lines.push(`  <program_name>${escapeXml(syslog.program)}</program_name>`);
    summaryParts.push(`program_name: ${syslog.program}`);
  }

  if (!syslog && jsonContext.location === "full") {
    lines.push("  <type>json</type>");
    lines.push("  <prematch>^\\{</prematch>");
    summaryParts.push("using JSON decoder directly on the raw event");
  } else if (jsonContext.prefix.trim()) {
    lines.push(`  <prematch>${escapeXml(buildPrematchFromPrefix(jsonContext.prefix))}</prematch>`);
    lines.push('  <plugin_decoder offset="after_prematch">JSON_Decoder</plugin_decoder>');
    lines.push("</decoder>");

    return {
      kind: "json",
      name,
      fields: [],
      xml: lines.join("\n"),
      summary: `${summaryParts.join(" • ")} • extracted dynamic fields: ${suggestions}`,
    };
  }

  lines.push("  <plugin_decoder>JSON_Decoder</plugin_decoder>");
  lines.push("</decoder>");

  return {
    kind: "json",
    name,
    fields: [],
    xml: lines.join("\n"),
    summary: `${summaryParts.join(" • ")} • extracted dynamic fields: ${suggestions}`,
  };
}

function buildRegexAnalysis({ rawLog, syslog, workingLog, name }) {
  const tokens = tokenizeLog(workingLog);
  const fields = [];
  const regexParts = ["^"];
  const usedFieldNames = new Map();
  let fallbackFieldCounter = 1;
  let seenIpCount = 0;

  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];

    if (token.type === "space") {
      regexParts.push("\\s+");
      continue;
    }

    const prevWord = getNearbyWord(tokens, index, -1);
    const nextWord = getNearbyWord(tokens, index, 1);
    const prevTwo = getNearbyWord(tokens, index, -2);
    const classification = classifyToken(
      token.value,
      prevWord,
      nextWord,
      prevTwo,
      seenIpCount
    );

    if (classification.capture) {
      if (classification.field === "srcip" || classification.field === "dstip") {
        seenIpCount += 1;
      }

      const fieldName =
        ensureUniqueFieldName(
          classification.field || `field_${fallbackFieldCounter++}`,
          usedFieldNames
        );
      fields.push({
        name: fieldName,
        sample: classification.sample,
        rawSample: token.value,
        pattern: classification.pattern,
        prematchHint: classification.prematchHint || "",
      });
      regexParts.push(classification.regexToken);
      continue;
    }

    regexParts.push(escapeRegex(token.value));
  }

  if (fields.length === 0) {
    const fallback = buildFallbackRegex(workingLog);
    fields.push({
      name: "data",
      sample: workingLog,
      pattern: fallback.pattern,
    });
    regexParts.length = 0;
    regexParts.push("^", fallback.regexBody, "$");
  } else {
    regexParts.push("$");
  }

  const prematch = syslog ? null : inferPrematch(workingLog, tokens, fields);
  const xml = renderRegexXml({
    name,
    syslog,
    prematch,
    regex: regexParts.join(""),
    fields,
  });

  return {
    kind: "regex",
    name,
    fields,
    prematch,
    regex: regexParts.join(""),
    syslog,
    workingLog,
    xml,
    summary: buildRegexSummary(rawLog, syslog, prematch, fields),
  };
}

function tokenizeLog(text) {
  const matches = text.match(/\s+|[^\s]+/gu) || [];
  return matches.map((value) => ({
    type: /\s/u.test(value) ? "space" : "word",
    value,
  }));
}

function getNearbyWord(tokens, startIndex, step) {
  let index = startIndex + step;
  while (tokens[index]) {
    if (tokens[index].type === "word") {
      return normalizeContextWord(tokens[index].value);
    }
    index += step;
  }
  return "";
}

function classifyToken(token, prevWord, nextWord, prevTwo, seenIpCount) {
  const parts = splitTokenEdges(token);
  const clean = parts.core;

  if (!clean) {
    return { capture: false };
  }

  const keyValueMatch = clean.match(/^([A-Za-z0-9_.-]+)=("?)(.+)\2$/u);
  if (keyValueMatch) {
    const value = keyValueMatch[3];
    const literalPrefix = `${parts.leading}${keyValueMatch[1]}=${keyValueMatch[2]}`;
    const literalSuffix = `${keyValueMatch[2]}${parts.trailing}`;
    return {
      capture: true,
      field: inferFieldFromKeyValue(keyValueMatch[1], value),
      pattern: buildValuePattern(value),
      sample: value,
      prematchHint: escapeRegex(literalPrefix),
      regexToken:
        escapeRegex(literalPrefix) +
        `(${buildValuePattern(value)})` +
        escapeRegex(literalSuffix),
    };
  }

  if (isUrl(clean)) {
    return buildCapturedToken(parts, "url", "https?:\\/\\/\\S+");
  }

  if (isIpv4(clean)) {
    const sourceHint = ["from", "src", "source", "client", "ip"].includes(prevWord);
    const destHint = ["to", "dst", "dest", "destination", "server"].includes(prevWord);
    const field = sourceHint
      ? "srcip"
      : destHint
        ? "dstip"
        : seenIpCount === 0
          ? "srcip"
          : "dstip";
    return buildCapturedToken(parts, field, "\\d{1,3}(?:\\.\\d{1,3}){3}");
  }

  if (isPortNumber(clean, prevWord, prevTwo)) {
    const field =
      ["dstport", "dport", "destination"].includes(prevWord) ||
      ["to", "dst", "dest"].includes(prevTwo)
        ? "dstport"
        : "srcport";
    return buildCapturedToken(parts, field, "\\d{1,5}");
  }

  if (isProtocol(clean, prevWord, nextWord)) {
    return buildCapturedToken(parts, "protocol", "[A-Za-z0-9._-]+");
  }

  if (isLikelyStatus(clean, prevWord)) {
    return buildCapturedToken(parts, "status", "[A-Za-z_-]+");
  }

  if (isLikelyAction(clean, prevWord)) {
    return buildCapturedToken(parts, "action", "[A-Za-z_-]+");
  }

  if (looksLikeIdentifier(clean, prevWord, nextWord)) {
    return buildCapturedToken(
      parts,
      inferFieldFromContext(prevWord, nextWord),
      "[A-Za-z0-9._:@/-]+"
    );
  }

  return { capture: false };
}

function buildCapturedToken(parts, field, pattern) {
  return {
    capture: true,
    field,
    pattern,
    sample: parts.core,
    prematchHint: escapeRegex(parts.leading),
    regexToken:
      escapeRegex(parts.leading) + `(${pattern})` + escapeRegex(parts.trailing),
  };
}

function buildFallbackRegex(log) {
  const trimmed = log.trim();
  const splitIndex = Math.max(trimmed.indexOf(":"), trimmed.indexOf("-"));

  if (splitIndex > 0) {
    return {
      regexBody:
        escapeRegex(trimmed.slice(0, splitIndex + 1)) + "\\s*(.+)",
      pattern: ".+",
    };
  }

  return {
    regexBody: "(.+)",
    pattern: ".+",
  };
}

function inferPrematch(log, tokens, fields) {
  if (!fields.length) {
    return "^";
  }

  const pieces = ["^"];

  for (const token of tokens) {
    if (token.type === "space") {
      pieces.push("\\s+");
      continue;
    }

    const isFieldSample = fields[0] && token.value === fields[0].rawSample;
    if (isFieldSample) {
      break;
    }

    pieces.push(escapeRegex(token.value));
  }

  const prematch = pieces.join("");
  if (prematch !== "^") {
    return prematch;
  }

  return fields[0]?.prematchHint ? `^${fields[0].prematchHint}` : "^.*";
}

function renderRegexXml({ name, syslog, prematch, regex, fields }) {
  const lines = [`<decoder name="${name}">`];

  if (syslog?.program) {
    lines.push(`  <program_name>${escapeXml(syslog.program)}</program_name>`);
  } else if (prematch) {
    lines.push(`  <prematch>${escapeXml(prematch)}</prematch>`);
  }

  lines.push(`  <regex type="pcre2">${escapeXml(regex)}</regex>`);
  lines.push(`  <order>${fields.map((field) => field.name).join(",")}</order>`);
  lines.push("</decoder>");

  return lines.join("\n");
}

function buildRegexSummary(rawLog, syslog, prematch, fields) {
  const parts = ["Detected text log"];

  if (syslog?.program) {
    parts.push(`program_name: ${syslog.program}`);
  } else if (prematch) {
    parts.push(`prematch: ${prematch}`);
  }

  parts.push(`captured fields: ${fields.map((field) => field.name).join(", ")}`);
  return parts.join(" • ");
}

function renderAnalysis() {
  if (!state.analysis) {
    renderEmpty("Enter a log line to generate a decoder.");
    return;
  }

  elements.summary.textContent = state.analysis.summary;
  elements.xmlOutput.textContent = state.analysis.xml;
  renderFieldEditor();
}

function renderFieldEditor() {
  const analysis = state.analysis;
  if (!analysis || analysis.kind !== "regex" || !analysis.fields.length) {
    elements.fieldEditor.hidden = true;
    elements.fieldList.innerHTML = "";
    return;
  }

  elements.fieldEditor.hidden = false;
  elements.fieldList.innerHTML = "";

  analysis.fields.forEach((field, index) => {
    const row = document.createElement("div");
    row.className = "field-row";

    const sample = document.createElement("div");
    sample.className = "field-pill";
    sample.innerHTML = `<span>Sample value</span><code>${escapeHtml(field.sample)}</code>`;

    const inputWrap = document.createElement("label");
    inputWrap.className = "field";
    inputWrap.innerHTML = '<span>Field name</span>';

    const input = document.createElement("input");
    input.type = "text";
    input.value = field.name;
    input.dataset.index = String(index);
    input.addEventListener("input", handleFieldRename);
    inputWrap.appendChild(input);

    const pattern = document.createElement("div");
    pattern.className = "field-pill";
    pattern.innerHTML = `<span>Regex pattern</span><code>${escapeHtml(field.pattern)}</code>`;

    row.appendChild(sample);
    row.appendChild(inputWrap);
    row.appendChild(pattern);
    elements.fieldList.appendChild(row);
  });
}

function handleFieldRename(event) {
  const index = Number(event.target.dataset.index);
  const analysis = state.analysis;
  if (!analysis || analysis.kind !== "regex" || Number.isNaN(index)) {
    return;
  }

  const proposedBase =
    sanitizeFieldName(event.target.value) || `field_${index + 1}`;
  const proposed = ensureUniqueRename(proposedBase, analysis.fields, index);
  analysis.fields[index].name = proposed;
  event.target.value = proposed;
  analysis.xml = renderRegexXml({
    name: analysis.name,
    syslog: analysis.syslog,
    prematch: analysis.prematch,
    regex: analysis.regex,
    fields: analysis.fields,
  });
  elements.xmlOutput.textContent = analysis.xml;
  elements.summary.textContent = buildRegexSummary(
    elements.sampleLog.value.trim(),
    analysis.syslog,
    analysis.prematch,
    analysis.fields
  );
}

function buildPrematchFromPrefix(prefix) {
  return escapeRegex(prefix.trimEnd()) + "\\s*";
}

function inferDecoderName(syslog, jsonContext, workingLog) {
  const source = syslog?.program || firstWords(workingLog, 3);
  const suffix = jsonContext ? "json" : "decoder";
  return sanitizeDecoderName(`${source}_${suffix}`) || "custom_wazuh_decoder";
}

function firstWords(text, count) {
  return (text.match(/[A-Za-z0-9_-]+/gu) || []).slice(0, count).join("_");
}

function summarizeJsonKeys(json) {
  if (Array.isArray(json)) {
    return `array payload with ${json.length} item${json.length === 1 ? "" : "s"}`;
  }

  const keys = Object.keys(json).slice(0, 6);
  if (!keys.length) {
    return "no top-level keys detected";
  }

  return keys.join(", ");
}

function sanitizeDecoderName(value) {
  return (value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64);
}

function sanitizeFieldName(value) {
  return (value || "")
    .toLowerCase()
    .replace(/[^a-z0-9_.]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function normalizeFieldName(value) {
  const normalized = sanitizeFieldName(value);
  return normalized || "data";
}

function inferFieldFromKeyValue(key, value) {
  const normalizedKey = sanitizeFieldName(key);

  if (["user", "username", "account"].includes(normalizedKey)) {
    return "dstuser";
  }

  if (["src", "src_ip", "source", "source_ip"].includes(normalizedKey)) {
    return isIpv4(value) ? "srcip" : "srcuser";
  }

  if (["dst", "dst_ip", "dest", "dest_ip", "destination"].includes(normalizedKey)) {
    return isIpv4(value) ? "dstip" : "dstuser";
  }

  if (["port", "src_port", "source_port"].includes(normalizedKey)) {
    return "srcport";
  }

  if (["dst_port", "dest_port", "destination_port"].includes(normalizedKey)) {
    return "dstport";
  }

  if (["proto", "protocol"].includes(normalizedKey)) {
    return "protocol";
  }

  if (["status", "result"].includes(normalizedKey)) {
    return "status";
  }

  if (normalizedKey === "action") {
    return "action";
  }

  if (["url", "uri"].includes(normalizedKey)) {
    return "url";
  }

  if (["id", "event_id", "request_id", "session_id", "trace_id"].includes(normalizedKey)) {
    return "id";
  }

  return normalizeFieldName(key);
}

function normalizeContextWord(value) {
  return splitTokenEdges(value).core.toLowerCase();
}

function splitTokenEdges(value) {
  const leadingMatch = value.match(/^[("'[\]{}]+/u);
  const trailingMatch = value.match(/[,"')\]{}:;]+$/u);
  const leading = leadingMatch ? leadingMatch[0] : "";
  const trailing = trailingMatch ? trailingMatch[0] : "";
  const core = value.slice(leading.length, value.length - trailing.length);
  return { leading, core, trailing };
}

function isUrl(value) {
  return /^https?:\/\//u.test(value);
}

function isIpv4(value) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/u.test(value);
}

function isPortNumber(value, prevWord, prevTwo) {
  return /^\d{1,5}$/u.test(value) && (prevWord === "port" || prevWord === "srcport" || prevWord === "dstport" || prevTwo === "port");
}

function isProtocol(value, prevWord, nextWord) {
  const candidate = value.toUpperCase();
  const known = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "SSH", "SSH2"];
  return known.includes(candidate) || prevWord === "proto" || prevWord === "protocol" || nextWord === "protocol";
}

function isLikelyStatus(value, prevWord) {
  const statusWords = ["failed", "failure", "success", "successful", "succeeded", "error", "ok"];
  return statusWords.includes(value.toLowerCase()) && ["status", "result", "login", ""].includes(prevWord);
}

function isLikelyAction(value, prevWord) {
  const actionWords = ["allowed", "denied", "blocked", "accepted", "dropped"];
  return actionWords.includes(value.toLowerCase()) || prevWord === "action";
}

function looksLikeIdentifier(value, prevWord, nextWord) {
  if (/^[A-Za-z][A-Za-z0-9_.@:-]*$/u.test(value) && value.length > 2) {
    const contextKeys = [
      "user",
      "username",
      "account",
      "id",
      "event",
      "session",
      "trace",
      "request",
      "rule",
      "alert",
      "for",
      "by",
    ];
    return contextKeys.includes(prevWord) || nextWord === "id";
  }

  if (/^[A-Fa-f0-9-]{8,}$/u.test(value)) {
    return true;
  }

  return false;
}

function inferFieldFromContext(prevWord, nextWord) {
  if (["by", "srcuser", "actor"].includes(prevWord)) {
    return "srcuser";
  }

  if (["for", "user", "username", "account"].includes(prevWord)) {
    return "dstuser";
  }

  if (["id", "event", "session", "trace", "request", "rule", "alert"].includes(prevWord)) {
    return "id";
  }

  if (nextWord === "id") {
    return "id";
  }

  return "data";
}

function buildValuePattern(value) {
  if (isIpv4(value)) {
    return "\\d{1,3}(?:\\.\\d{1,3}){3}";
  }
  if (/^\d+$/u.test(value)) {
    return "\\d+";
  }
  return "[A-Za-z0-9._:@/-]+";
}

function escapeRegex(value) {
  return value.replace(/[|\\{}()[\]^$+*?.]/gu, "\\$&");
}

function ensureUniqueFieldName(name, usedFieldNames) {
  const currentCount = usedFieldNames.get(name) || 0;
  usedFieldNames.set(name, currentCount + 1);

  if (currentCount === 0) {
    return name;
  }

  return `${name}_${currentCount + 1}`;
}

function ensureUniqueRename(name, fields, currentIndex) {
  let candidate = name;
  let suffix = 2;

  while (
    fields.some((field, index) => index !== currentIndex && field.name === candidate)
  ) {
    candidate = `${name}_${suffix}`;
    suffix += 1;
  }

  return candidate;
}

function escapeXml(value) {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;")
    .replace(/"/gu, "&quot;")
    .replace(/'/gu, "&apos;");
}

function escapeHtml(value) {
  return value
    .replace(/&/gu, "&amp;")
    .replace(/</gu, "&lt;")
    .replace(/>/gu, "&gt;");
}
