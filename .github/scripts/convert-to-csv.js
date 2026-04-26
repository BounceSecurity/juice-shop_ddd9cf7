const fs = require("fs");
const path = require("path");

const inputPath = process.argv[2];
if (!inputPath) {
  console.error("Usage: node convert-to-csv.js <vulnerabilities.json>");
  process.exit(1);
}

const outputDir = path.dirname(inputPath);
const data = JSON.parse(fs.readFileSync(inputPath, "utf8"));

// Build lookup maps
const components = Object.fromEntries(
  (data.components || []).map((c) => [c.key, c])
);
const rules = Object.fromEntries(
  (data.rules || []).map((r) => [r.key, r])
);

function escapeCsv(value) {
  if (value == null) return "";
  const str = String(value);
  if (str.includes(",") || str.includes('"') || str.includes("\n")) {
    return '"' + str.replace(/"/g, '""') + '"';
  }
  return str;
}

function csvRow(fields) {
  return fields.map(escapeCsv).join(",");
}

// Strip project key prefix from component paths
function componentPath(componentKey) {
  const prefix = data.issues[0]?.project;
  if (prefix && componentKey.startsWith(prefix + ":")) {
    return componentKey.slice(prefix.length + 1);
  }
  return componentKey;
}

// --- Issues CSV ---
const issueHeaders = [
  "key",
  "rule",
  "ruleName",
  "severity",
  "impactSeverity",
  "status",
  "message",
  "component",
  "line",
  "effort",
  "cleanCodeAttribute",
  "cleanCodeAttributeCategory",
  "tags",
  "assignee",
  "author",
  "creationDate",
  "updateDate",
];

const issueRows = data.issues.map((issue) => {
  const rule = rules[issue.rule];
  const securityImpact = (issue.impacts || []).find(
    (i) => i.softwareQuality === "SECURITY"
  );
  return csvRow([
    issue.key,
    issue.rule,
    rule?.name || "",
    issue.severity,
    securityImpact?.severity || "",
    issue.issueStatus || issue.status,
    issue.message,
    componentPath(issue.component),
    issue.line,
    issue.effort,
    issue.cleanCodeAttribute,
    issue.cleanCodeAttributeCategory,
    (issue.tags || []).join("; "),
    issue.assignee,
    issue.author,
    issue.creationDate,
    issue.updateDate,
  ]);
});

const issuesCsv = [csvRow(issueHeaders), ...issueRows].join("\n") + "\n";
const issuesPath = path.join(outputDir, "issues.csv");
fs.writeFileSync(issuesPath, issuesCsv);
console.log(`Wrote ${data.issues.length} issues to ${issuesPath}`);

// --- Flows CSV ---
const flowHeaders = [
  "issueKey",
  "flowIndex",
  "locationIndex",
  "component",
  "startLine",
  "endLine",
  "message",
];

const flowRows = [];
for (const issue of data.issues) {
  for (let fi = 0; fi < (issue.flows || []).length; fi++) {
    const flow = issue.flows[fi];
    for (let li = 0; li < flow.locations.length; li++) {
      const loc = flow.locations[li];
      flowRows.push(
        csvRow([
          issue.key,
          fi + 1,
          li + 1,
          componentPath(loc.component),
          loc.textRange?.startLine,
          loc.textRange?.endLine,
          loc.msg,
        ])
      );
    }
  }
}

const flowsCsv = [csvRow(flowHeaders), ...flowRows].join("\n") + "\n";
const flowsPath = path.join(outputDir, "flows.csv");
fs.writeFileSync(flowsPath, flowsCsv);
console.log(`Wrote ${flowRows.length} flow locations to ${flowsPath}`);
