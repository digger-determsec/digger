// batch_compile.js — Compile all corpus Solidity sources to runtime bytecode
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = path.resolve(__dirname, '../../..');
const corpusDir = path.join(root, 'corpus/known-exploits');
const outDir = path.join(root, 'crates/digger-benchmark/fixtures/bytecode/evm_compiled');

fs.mkdirSync(outDir, { recursive: true });

function findSol(dir) {
    const results = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) results.push(...findSol(p));
        else if (entry.name.endsWith('.sol')) results.push(p);
    }
    return results;
}

const solFiles = findSol(corpusDir);
console.log(`Found ${solFiles.length} Solidity files`);

let compiled = 0;
let failed = 0;
const compiledCases = [];

for (const solFile of solFiles) {
    const relPath = path.relative(root, solFile);
    const source = fs.readFileSync(solFile, 'utf8');
    
    const input = JSON.stringify({
        language: 'Solidity',
        sources: { 'source.sol': { content: source } },
        settings: { 
            outputSelection: { '*': { '*': ['evm.deployedBytecode.object'] } },
            optimizer: { enabled: true, runs: 200 }
        }
    });
    
    try {
        const raw = execSync('npx solc --standard-json', { input, timeout: 30000 }).toString();
        const jsonStart = raw.indexOf('{');
        if (jsonStart < 0) { failed++; continue; }
        const output = JSON.parse(raw.substring(jsonStart));
        
        if (output.errors && output.errors.some(e => e.severity === 'error')) {
            failed++;
            continue;
        }
        
        if (!output.contracts) { failed++; continue; }
        
        // Get case_id from meta.json
        const dir = path.dirname(solFile);
        const metaPath = path.join(dir, 'meta.json');
        let caseId = path.basename(dir);
        if (fs.existsSync(metaPath)) {
            try { caseId = JSON.parse(fs.readFileSync(metaPath, 'utf8')).exploit_id || caseId; } catch(e) {}
        }
        
        for (const file of Object.keys(output.contracts)) {
            for (const name of Object.keys(output.contracts[file])) {
                const deployed = output.contracts[file][name]?.evm?.deployedBytecode?.object;
                if (deployed && deployed.length > 0) {
                    const outPath = path.join(outDir, `${caseId}.hex`);
                    fs.writeFileSync(outPath, deployed);
                    compiledCases.push(caseId);
                    compiled++;
                }
            }
        }
    } catch (e) {
        failed++;
    }
}

console.log(`Compiled: ${compiled}, Failed/Skipped: ${failed}`);
console.log(`Cases: ${compiledCases.join(', ')}`);
