'use strict';
// DEC-AUP-0147: inspect immutable compiler input; never execute consumer code.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
/** @typedef {import('typescript').Node} TsNode */
/** @typedef {import('typescript').SourceFile} TsSourceFile */
/** @typedef {import('typescript').ClassDeclaration & {name: import('typescript').Identifier}} NamedClass */
/** @typedef {{root: string, root_module_file: string, candidates: string[], compilerOptions: Record<string, unknown>, files: {path: string, text: string}[]}} CompilerInput */
/** @typedef {{start_utf8: number, end_utf8: number}} Utf8Span */
/** @typedef {{module_name: string|null, span: Utf8Span|null, verdict: 'verified'|'not_measured'|'failed'}} Registration */
/** @typedef {{node: NamedClass, module: import('typescript').CallExpression|undefined, controller: import('typescript').CallExpression|undefined, rawController: boolean, controllers: string[]|null, imports: string[]|null}} ClassEntry */
/** @typedef {{node: import('typescript').CallExpression, imports: string[]|null, controllers: string[]|null}} TestRoot */
/** @typedef {{path: string, class_name: string, span: Utf8Span, scope: 'unknown'|'fixture'|'production', reason_codes: string[], production_reachable: 'true'|'false'|'unknown', test_module_registration: Registration, route_spans: Utf8Span[]}} ControllerFact */
/** @typedef {{schema: string, compiler_version: string, controllers: ControllerFact[], reached_sources: string[], production_unknown: string[], identity_inputs: {file: string, sha256: string}[]}} CompilerFacts */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
/** @param {unknown} value @returns {value is CompilerInput} */
function isCompilerInput(value) {
  if (!isRecord(value) || typeof value.root !== 'string' || typeof value.root_module_file !== 'string' ||
      !isRecord(value.compilerOptions) || !Array.isArray(value.files) || !Array.isArray(value.candidates)) return false;
  /** @type {unknown[]} */
  const files = value.files;
  /** @type {unknown[]} */
  const candidates = value.candidates;
  return candidates.every(p => typeof p === 'string') &&
    files.every(f => isRecord(f) && typeof f.path === 'string' && typeof f.text === 'string');
}
/** @type {typeof import('typescript')} */
const ts = require(process.argv[2]);
/** @type {unknown} */
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
if (!isCompilerInput(input)) throw new Error('INVALID_COMPILER_INPUT');
const root = input.root;
const sources = new Map(input.files.map(f => [path.join(root, f.path), f.text]));
const host = ts.createCompilerHost({});
const readPhysical = host.readFile.bind(host);
const existsPhysical = host.fileExists.bind(host);
/** @param {string} p */
const isProject = p => p.startsWith(root + path.sep) && !p.includes(path.sep + 'node_modules' + path.sep);
/** @param {string} p */
host.readFile = p => sources.has(p) ? sources.get(p) : isProject(p) ? undefined : readPhysical(p);
/** @param {string} p */
host.fileExists = p => sources.has(p) || (!isProject(p) && existsPhysical(p));
/** @param {string} p @param {import('typescript').ScriptTarget|import('typescript').CreateSourceFileOptions} version */
host.getSourceFile = (p, version) => {
  const text = host.readFile(p);
  return text === undefined ? undefined : ts.createSourceFile(p, text, version, true,
    p.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
};
const options = ts.convertCompilerOptionsFromJson(input.compilerOptions, root);
const rootFile = path.join(root, input.root_module_file);
const program = ts.createProgram([rootFile, ...input.candidates.map(p => path.join(root, p))], options.options, host);
const checker = program.getTypeChecker();
/** @type {Map<string, string[]>} */
const edges = new Map();
/** @type {Map<string, string[]>} */
const unresolved = new Map();
/** @type {Map<string, string>} */
const dependencyInputs = new Map();
/** @type {Map<string, ClassEntry>} */
const classes = new Map();
/** @type {TestRoot[]} */
const testRoots = [];
/** @param {TsNode} n @returns {Utf8Span} */
const span = n => {
  const s = n.getSourceFile();
  return {start_utf8: Buffer.byteLength(s.text.slice(0, n.getStart(s))), end_utf8: Buffer.byteLength(s.text.slice(0, n.end))};
};
/** @param {TsNode} n */
const key = n => n.getSourceFile().fileName + ':' + n.pos + ':' + n.end;
/** @param {TsNode} node */
function symbol(node) {
  let s = checker.getSymbolAtLocation(node);
  if (s && (s.flags & ts.SymbolFlags.Alias)) s = checker.getAliasedSymbol(s);
  return s;
}
/** @param {TsNode} node @param {string} exported @param {string} module */
function origin(node, exported, module) {
  const s = symbol(node);
  if (!s || s.name !== exported || !s.declarations?.length) return false;
  return s.declarations.every(d => {
    const source = d.getSourceFile();
    const marker = path.sep + 'node_modules' + path.sep + module + path.sep;
    if (!source.fileName.includes(marker) || sources.has(source.fileName)) return false;
    dependencyInputs.set(source.fileName, crypto.createHash('sha256').update(source.text).digest('hex'));
    return true;
  });
}
/** @param {TsNode} node */
function reference(node) {
  const s = symbol(node);
  return s?.declarations?.find(ts.isClassDeclaration);
}
/** @param {import('typescript').ClassDeclaration} node @param {string} name */
function decorator(node, name) {
  for (const d of ts.getDecorators(node) || []) {
    const expr = d.expression;
    if (!ts.isCallExpression(expr)) continue;
    const called = ts.isPropertyAccessExpression(expr.expression) ? expr.expression.name : expr.expression;
    if (origin(called, name, '@nestjs/common')) return expr;
  }
  return undefined;
}
/** @param {import('typescript').Expression} object @param {string} name @returns {string[]|null} */
function list(object, name) {
  if (!ts.isObjectLiteralExpression(object) || object.properties.some(p =>
      !ts.isPropertyAssignment(p) || !(ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)))) return null;
  // The preceding guard validates every property and its simple name.
  const properties = /** @type {readonly (import('typescript').PropertyAssignment & {name: import('typescript').Identifier|import('typescript').StringLiteral})[]} */ (object.properties);
  const props = properties.filter(p => p.name.text === name);
  if (!props.length) return [];
  if (props.length !== 1 || !ts.isArrayLiteralExpression(props[0].initializer)) return null;
  const declarations = props[0].initializer.elements.map(reference);
  return declarations.every(Boolean) ? /** @type {import('typescript').ClassDeclaration[]} */ (declarations).map(key) : null;
}
/** @param {TsSourceFile} source */
function hasParseErrors(source) {
  // This compiler-owned metadata is not exposed by the public SourceFile type.
  /** @type {unknown} */
  const diagnostics = Reflect.get(source, 'parseDiagnostics');
  if (!Array.isArray(diagnostics)) throw new Error('COMPILER_PARSE_DIAGNOSTICS_UNRESOLVED');
  return diagnostics.length !== 0;
}
for (const source of program.getSourceFiles()) {
  if (!sources.has(source.fileName)) continue;
  /** @type {string[]} */
  const next = [];
  /** @type {string[]} */
  const unknown = [];
  if (hasParseErrors(source)) unknown.push('SOURCE_PARSE_ERROR');
  /** @param {TsNode} node */
  function visit(node) {
    // Only the direct literal loader forms below have a proved static edge.
    // A loader reference can escape through aliases, properties, destructuring,
    // callbacks or reassignment. Do not claim containment by overlooking it.
    // Conservatively refuse also the module builtin: createRequire may be
    // renamed or accessed with a computed key, so its spelling is not proof.
    if (ts.isIdentifier(node) && ['require', 'eval'].includes(node.text)) {
      const parent = node.parent;
      const direct = ts.isCallExpression(parent) && parent.expression === node;
      if (!direct) unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
    }
    if ((ts.isIdentifier(node) || ts.isStringLiteral(node)) && node.text === 'createRequire') {
      unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
    }
    // The CommonJS module object can yield a loader through an opaque key or
    // another alias. Static module.exports does not expose that capability.
    if (ts.isIdentifier(node) && node.text === 'module' &&
        !(ts.isPropertyAccessExpression(node.parent) && node.parent.expression === node &&
          node.parent.name.text === 'exports')) {
      unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
    }
    if (ts.isStringLiteral(node) && ['require', 'eval'].includes(node.text) &&
        (ts.isElementAccessExpression(node.parent) || ts.isBindingElement(node.parent))) {
      unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
    }
    if (ts.isImportEqualsDeclaration(node) && !node.isTypeOnly) {
      // TypeScript import-equals has no CallExpression require node, but its
      // external module reference emits a real runtime require. Type-only
      // references and ImportTypeNode expressions emit no runtime loader.
      const reference = node.moduleReference;
      if (ts.isExternalModuleReference(reference)) {
        const expression = reference.expression;
        if (expression && ts.isStringLiteral(expression)) {
          const spec = expression.text;
          if (['module', 'node:module'].includes(spec)) unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
          const resolved = ts.resolveModuleName(spec, source.fileName, options.options, host).resolvedModule;
          if (resolved) next.push(resolved.resolvedFileName);
          else unknown.push('UNRESOLVED_PRODUCTION_IMPORT');
        } else unknown.push('DYNAMIC_MODULE_SPECIFIER');
      } else unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
    }
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (ts.isStringLiteral(node.moduleSpecifier)) {
        const spec = node.moduleSpecifier.text;
        if (['module', 'node:module'].includes(spec)) unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
        const resolved = ts.resolveModuleName(spec, source.fileName, options.options, host).resolvedModule;
        if (resolved) next.push(resolved.resolvedFileName);
        else if (spec.startsWith('.') || spec.startsWith('@/')) unknown.push('UNRESOLVED_PRODUCTION_IMPORT');
      } else unknown.push('DYNAMIC_MODULE_SPECIFIER');
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        ts.isIdentifier(node.expression) && ['require', 'eval'].includes(node.expression.text))) {
      if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') unknown.push('DYNAMIC_PRODUCTION_EVAL');
      else if (node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0])) {
        const spec = node.arguments[0].text;
        if (['module', 'node:module'].includes(spec)) unknown.push('UNSUPPORTED_PRODUCTION_LOADER');
        const resolved = ts.resolveModuleName(spec, source.fileName, options.options, host).resolvedModule;
        if (resolved) next.push(resolved.resolvedFileName);
        else if (spec.startsWith('.') || spec.startsWith('@/')) unknown.push('UNRESOLVED_PRODUCTION_IMPORT');
      } else unknown.push('DYNAMIC_PRODUCTION_IMPORT');
    }
    if (ts.isClassDeclaration(node) && node.name) {
      const module = decorator(node, 'Module');
      const controller = decorator(node, 'Controller');
      const rawController = (ts.getDecorators(node) || []).some(d => /^Controller\b/.test(d.expression.getText(source)));
      /** @type {ClassEntry} */
      const entry = {node: /** @type {NamedClass} */ (node), module, controller, rawController, controllers: null, imports: null};
      if (module) {
        entry.controllers = module.arguments.length === 1 ? list(module.arguments[0], 'controllers') : null;
        entry.imports = module.arguments.length === 1 ? list(module.arguments[0], 'imports') : null;
      }
      classes.set(key(node), entry);
    }
    if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression) &&
        node.expression.name.text === 'createTestingModule' && origin(node.expression.expression, 'Test', '@nestjs/testing')) {
      const imports = node.arguments.length === 1 ? list(node.arguments[0], 'imports') : null;
      const controllers = node.arguments.length === 1 ? list(node.arguments[0], 'controllers') : null;
      testRoots.push({node, imports, controllers});
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  edges.set(source.fileName, next);
  unresolved.set(source.fileName, unknown);
}
const reached = new Set();
const pending = [rootFile];
while (pending.length) {
  const p = /** @type {string} */ (pending.pop());
  if (reached.has(p)) continue;
  reached.add(p);
  pending.push(...(edges.get(p) || []));
}
const productionUnknown = [...reached].flatMap(p => unresolved.get(p) || []);
if (options.errors.length) productionUnknown.push('COMPILER_OPTIONS_UNRESOLVED');
/** @param {string} controllerKey @param {string} sourceFile @returns {Registration} */
function registration(controllerKey, sourceFile) {
  let unknown = false;
  for (const test of testRoots.filter(t => t.node.getSourceFile().fileName === sourceFile)) {
    if (test.imports === null || test.controllers === null) {unknown = true; continue;}
    if (test.controllers.includes(controllerKey)) return {module_name: 'Test.createTestingModule', span: span(test.node), verdict: 'verified'};
    const queue = [...test.imports]; const seen = new Set();
    while (queue.length) {
      const id = /** @type {string} */ (queue.pop()); if (seen.has(id)) continue; seen.add(id);
      const module = classes.get(id);
      if (!module?.module || module.controllers === null || module.imports === null) {unknown = true; continue;}
      if (module.controllers.includes(controllerKey)) return {module_name: module.node.name.text, span: span(module.node), verdict: 'verified'};
      queue.push(...module.imports);
    }
  }
  return {module_name: null, span: null, verdict: unknown ? 'not_measured' : 'failed'};
}
/** @type {CompilerFacts} */
const output = {schema: 'InlineNestHarnessCompilerFacts/v1', compiler_version: ts.version, controllers: [],
  reached_sources: [...reached].filter(p => sources.has(p)).map(p => path.relative(root, p)).sort(),
  production_unknown: [...new Set(productionUnknown)], identity_inputs: []};
for (const [id, entry] of classes) {
  const source = entry.node.getSourceFile();
  const relative = path.relative(root, source.fileName);
  if (!input.candidates.includes(relative) || !(entry.controller || entry.rawController)) continue;
  const reg = registration(id, source.fileName);
  const reasons = [];
  const routes = [];
  let routesKnown = true;
  for (const member of entry.node.members) {
    // Read the public modifier surface, retaining legacy constructor decorator
    // observations as well as the supported decorator-bearing class members.
    if (!ts.canHaveModifiers(member)) continue;
    for (const d of member.modifiers || []) {
      if (!ts.isDecorator(d) || !ts.isCallExpression(d.expression)) continue;
      const called = ts.isPropertyAccessExpression(d.expression.expression) ? d.expression.expression.name : d.expression.expression;
      if (ts.isIdentifier(called) && ['Get','Post','Put','Patch','Delete','Head','Options','All'].includes(called.text)) {
        if (!origin(called, called.text, '@nestjs/common')) routesKnown = false;
        routes.push(span(d));
      }
    }
  }
  const production = reached.has(source.fileName);
  /** @type {ControllerFact['scope']} */
  let scope = 'unknown';
  if (production && entry.controller) scope = 'production';
  else if (entry.controller && routesKnown && !productionUnknown.length && reg.verdict === 'verified' && !hasParseErrors(source)) scope = 'fixture';
  else reasons.push(...productionUnknown, !entry.controller || !routesKnown ? 'DECORATOR_IDENTITY_UNRESOLVED' : 'TEST_MODULE_REGISTRATION_UNPROVED');
  output.controllers.push({path: relative, class_name: entry.node.name.text, span: span(entry.node), scope,
    reason_codes: [...new Set(reasons)], production_reachable: production ? 'true' : productionUnknown.length ? 'unknown' : 'false',
    test_module_registration: reg, route_spans: routes});
}
output.identity_inputs = [...dependencyInputs].map(([file, sha256]) => ({file, sha256}));
process.stdout.write(JSON.stringify(output));
