#!/usr/bin/env node
/*
 * Offline syntax + semantic validation of detections/kql/defender-xdr-hunting.kql
 * using Microsoft's Kusto.Language parser (npm: @kusto/language-service-next).
 *
 *   npm install @kusto/language-service-next
 *   node tests/validate_kql.js [path/to/file.kql] [path/to/node_modules]
 *
 * The Defender XDR tables are declared below from the published advanced-hunting schema
 * reference (learn.microsoft.com/defender-xdr/advanced-hunting-schema-tables), so unknown
 * column names and type errors are reported, not just syntax errors.
 */
const fs = require("fs");
const path = require("path");

const kqlFile = process.argv[2] || path.join(__dirname, "..", "detections", "kql", "defender-xdr-hunting.kql");
const modDir = path.resolve(process.argv[3] || path.join(process.cwd(), "node_modules"));
const pkg = path.join(modDir, "@kusto", "language-service-next");
require(path.join(pkg, "bridge.js"));
require(path.join(pkg, "Kusto.Language.Bridge.js"));
const K = global.Kusto.Language;

const initiating = [
  "InitiatingProcessAccountDomain:string", "InitiatingProcessAccountName:string", "InitiatingProcessAccountSid:string",
  "InitiatingProcessAccountUpn:string", "InitiatingProcessAccountObjectId:string", "InitiatingProcessIntegrityLevel:string",
  "InitiatingProcessTokenElevation:string", "InitiatingProcessSHA1:string", "InitiatingProcessSHA256:string",
  "InitiatingProcessMD5:string", "InitiatingProcessFileName:string", "InitiatingProcessFileSize:long",
  "InitiatingProcessVersionInfoCompanyName:string", "InitiatingProcessVersionInfoProductName:string",
  "InitiatingProcessVersionInfoProductVersion:string", "InitiatingProcessVersionInfoInternalFileName:string",
  "InitiatingProcessVersionInfoOriginalFileName:string", "InitiatingProcessVersionInfoFileDescription:string",
  "InitiatingProcessId:long", "InitiatingProcessCommandLine:string", "InitiatingProcessCreationTime:datetime",
  "InitiatingProcessFolderPath:string", "InitiatingProcessParentId:long", "InitiatingProcessParentFileName:string",
  "InitiatingProcessParentCreationTime:datetime", "InitiatingProcessSignerType:string",
  "InitiatingProcessSignatureStatus:string", "InitiatingProcessSessionId:long", "InitiatingProcessUniqueId:string",
];
const common = ["Timestamp:datetime", "DeviceId:string", "DeviceName:string", "ActionType:string"];
const fileCols = ["FileName:string", "FolderPath:string", "SHA1:string", "SHA256:string", "MD5:string", "FileSize:long"];
const tail = ["ReportId:long", "AppGuardContainerId:string", "AdditionalFields:dynamic"];

const schemas = {
  DeviceProcessEvents: [...common, ...fileCols,
    "ProcessVersionInfoCompanyName:string", "ProcessVersionInfoProductName:string", "ProcessVersionInfoProductVersion:string",
    "ProcessVersionInfoInternalFileName:string", "ProcessVersionInfoOriginalFileName:string",
    "ProcessVersionInfoFileDescription:string", "ProcessId:long", "ProcessCommandLine:string",
    "ProcessIntegrityLevel:string", "ProcessTokenElevation:string", "ProcessCreationTime:datetime",
    "AccountDomain:string", "AccountName:string", "AccountSid:string", "AccountUpn:string", "AccountObjectId:string",
    "LogonId:long", ...initiating, ...tail],
  DeviceImageLoadEvents: [...common, ...fileCols, ...initiating, ...tail],
  DeviceNetworkEvents: [...common, "RemoteIP:string", "RemotePort:int", "RemoteUrl:string", "LocalIP:string",
    "LocalPort:int", "Protocol:string", "LocalIPType:string", "RemoteIPType:string", ...initiating, ...tail],
  DeviceRegistryEvents: [...common, "RegistryKey:string", "RegistryValueType:string", "RegistryValueName:string",
    "RegistryValueData:string", "PreviousRegistryKey:string", "PreviousRegistryValueName:string",
    "PreviousRegistryValueData:string", ...initiating, ...tail],
  DeviceFileEvents: [...common, ...fileCols, "FileOriginUrl:string", "FileOriginReferrerUrl:string",
    "FileOriginIP:string", "PreviousFolderPath:string", "PreviousFileName:string", "RequestProtocol:string",
    "RequestSourceIP:string", "RequestSourcePort:int", "RequestAccountName:string", "RequestAccountDomain:string",
    "RequestAccountSid:string", "ShareName:string", "SensitivityLabel:string", "SensitivitySubLabel:string",
    "IsAzureInfoProtectionApplied:bool", ...initiating, ...tail],
  DeviceLogonEvents: [...common, "LogonType:string", "AccountDomain:string", "AccountName:string", "AccountSid:string",
    "Protocol:string", "FailureReason:string", "IsLocalAdmin:bool", "LogonId:long", "RemoteDeviceName:string",
    "RemoteIP:string", "RemoteIPType:string", "RemotePort:int", ...initiating, ...tail],
  DeviceEvents: [...common, ...fileCols, "AccountDomain:string", "AccountName:string", "AccountSid:string",
    "RemoteUrl:string", "RemoteDeviceName:string", "ProcessId:long", "ProcessCommandLine:string",
    "ProcessCreationTime:datetime", "ProcessTokenElevation:string", "LogonId:long", "RegistryKey:string",
    "RegistryValueName:string", "RegistryValueData:string", "RemoteIP:string", "RemotePort:int", "LocalIP:string",
    "LocalPort:int", "FileOriginUrl:string", "FileOriginIP:string", ...initiating, ...tail],
};

const tables = Object.entries(schemas).map(([name, cols]) =>
  K.Symbols.TableSymbol.From("(" + cols.join(", ") + ")").WithName(name));
const db = new K.Symbols.DatabaseSymbol.ctor("DefenderXDR", tables);
const globals = K.GlobalState.Default.WithDatabase(db);

// Split into query blocks on the "// ----" header lines.
const text = fs.readFileSync(kqlFile, "utf8");
const chunks = text.split(/^\/\/ -{20,}\s*$/m);
let blocks = [];
for (let i = 0; i < chunks.length; i++) {
  const body = chunks[i].split("\n").filter(l => !/^\s*\/\//.test(l)).join("\n").trim();
  if (!body) continue;
  const title = (chunks[i - 1] || "").split("\n").map(l => l.trim()).find(l => /^\/\/ Q\d+/.test(l)) || `block ${i}`;
  blocks.push({ title: title.replace(/^\/\/\s*/, ""), body });
}

function toArray(list) {
  const out = [];
  const n = list.Count !== undefined ? list.Count : System.Array.getCount(list);
  for (let i = 0; i < n; i++) out.push(list.getItem ? list.getItem(i) : System.Array.getItem(list, i));
  return out;
}

let failed = 0;
for (const b of blocks) {
  const code = K.KustoCode.ParseAndAnalyze(b.body, globals);
  const diags = toArray(code.GetDiagnostics()).filter(d => String(d.Severity) === "Error");
  if (diags.length) {
    failed++;
    console.log(`FAIL  ${b.title}`);
    for (const d of diags) console.log(`      ${d.Code}: ${d.Message}  @${d.Start}  "${b.body.substr(d.Start, Math.max(1, d.Length))}"`);
  } else {
    console.log(`ok    ${b.title}`);
  }
}
console.log(`\n${blocks.length} queries, ${failed} with errors`);
process.exit(failed ? 1 : 0);
