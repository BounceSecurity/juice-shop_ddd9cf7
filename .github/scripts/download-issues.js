const fs = require("fs");
const path = require("path");
const https = require("https");

const PROJECT_KEY = "bounce-security_juiceshop-ddd9cf7";
const BASE_URL = "https://sonarcloud.io/api/issues/search";
const PAGE_SIZE = 500;

const token = process.env.SONAR_TOKEN;
if (!token) {
  console.error("Error: SONAR_TOKEN environment variable is required");
  process.exit(1);
}

const outputDir = process.argv[2] || "reports";
fs.mkdirSync(outputDir, { recursive: true });

function fetch(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(
      url,
      {
        headers: {
          Authorization:
            "Basic " + Buffer.from(token + ":").toString("base64"),
        },
      },
      (res) => {
        if (res.statusCode !== 200) {
          let body = "";
          res.on("data", (chunk) => (body += chunk));
          res.on("end", () =>
            reject(new Error(`HTTP ${res.statusCode}: ${body}`))
          );
          return;
        }
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => resolve(JSON.parse(body)));
      }
    );
    req.on("error", reject);
  });
}

async function main() {
  const allIssues = [];
  let allComponents = [];
  let allRules = [];
  let page = 1;
  let total;

  do {
    const params = new URLSearchParams({
      componentKeys: PROJECT_KEY,
      types: "VULNERABILITY",
      ps: PAGE_SIZE,
      p: page,
      additionalFields: "comments,rules",
    });

    console.log(`Fetching issues page ${page}...`);
    const data = await fetch(`${BASE_URL}?${params}`);
    total = data.paging.total;

    allIssues.push(...data.issues);
    allComponents.push(...(data.components || []));
    allRules.push(...(data.rules || []));

    console.log(`Page ${page} fetched. Total issues: ${total}`);
    page++;
  } while ((page - 1) * PAGE_SIZE < total);

  // Deduplicate components and rules
  const seen = new Set();
  allComponents = allComponents.filter((c) =>
    seen.has(c.key) ? false : (seen.add(c.key), true)
  );
  seen.clear();
  allRules = allRules.filter((r) =>
    seen.has(r.key) ? false : (seen.add(r.key), true)
  );

  const result = {
    total,
    issues: allIssues,
    components: allComponents,
    rules: allRules,
  };

  const outputPath = path.join(outputDir, "vulnerabilities.json");
  fs.writeFileSync(outputPath, JSON.stringify(result, null, 2));
  console.log(`Total vulnerabilities exported: ${total}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
