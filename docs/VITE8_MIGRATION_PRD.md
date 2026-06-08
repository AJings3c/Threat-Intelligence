# Vite 8 Migration PRD

## 1. Objective

Upgrade the frontend build chain from Vite 5 to Vite 8 while preserving all existing product behavior. The migration must remove the current Vite/esbuild moderate audit findings, keep the threat-intelligence UI functional, and adapt any affected code or configuration to the Vite 8 Rolldown/Oxc toolchain.

## 2. Background

The project currently uses a React 18 + TypeScript + Tailwind frontend served by Vite. `npm audit` reports moderate findings in the Vite/esbuild development server stack. Vite 8 is the current supported major line and changes the build pipeline to Rolldown/Oxc. The local development environment is Node `v24.8.0` with npm `11.6.0`, and the Docker image uses Node 22, so the runtime family is compatible with Vite 8.

Vite 8 requires Node `20.19+` or `22.12+`. The repository must therefore advertise that requirement explicitly so older Node 20 patch versions do not pass the package engine check but fail during Vite execution.

## 3. Functional Requirements

The migration must preserve these product capabilities:

- Overview workspace: source health, stats, map, CVE list, trend panel, and Hash/Malware intel render correctly.
- Sources & Config workspace: configuration status, refresh/check button, single-source test buttons, enrichment provider test buttons, and notification test button still call the expected API endpoints.
- Investigation workspace: global IOC command, panel IOC search, recent investigation replay, enrichment, Markdown/JSON export, source-backed graph, and graph/list toggle remain usable.
- Threat Modeling workspace: model refresh, Markdown export, architecture graph, graph/list toggle, scenarios, assets/data flows, STRIDE matrix, controls, and attack paths remain usable.
- Intel Feed workspace: filters, table selection, details panel, clear-selection action, and reference links remain usable.
- Cross-cutting UX: English/Chinese switch, desktop/mobile layout, focus states, no horizontal overflow, and no browser console errors must be preserved.

## 4. Technical Requirements

- Upgrade `vite` to `^8.0.16`.
- Upgrade `@vitejs/plugin-react` to `^6.0.2`.
- Update the root `package-lock.json`.
- Tighten the root Node engine to `>=20.19`.
- Keep the existing Vite proxy behavior: `/api` goes to `VITE_API_PROXY ?? http://localhost:4000`.
- Keep `build.outDir = "dist"` and `sourcemap = false`.
- Do not enable Vite 8 optional features by default, including DevTools, `resolve.tsconfigPaths`, or full bundle mode.
- Do not upgrade React, Tailwind, TypeScript, or ESLint unless the Vite 8 migration proves it is required.
- If dynamic import, CSS chunking, map rendering, or React Flow graph rendering changes under Vite 8, adapt the affected import/configuration instead of removing the feature.

## 5. Impact Assessment

Expected low-risk areas:

- The current `frontend/vite.config.ts` is small and uses only the official React plugin, dev proxy, and build output settings.
- Docker uses Node 22, which is compatible with Vite 8.
- The frontend uses ordinary ESM imports, Tailwind/PostCSS, and Vite env variables.

Expected higher-risk areas:

- `@xyflow/react` graph lazy loading and CSS chunk emission.
- `world-atlas` JSON import and map rendering.
- React Refresh behavior from `@vitejs/plugin-react` 6.
- Dev proxy behavior for `/api` endpoints.
- Production bundle splitting and static asset paths.

If any of these areas breaks during debugging, the affected functionality must be adapted as part of the migration.

## 6. Acceptance Criteria

The migration is accepted only when all of the following pass:

- `node -v` satisfies the documented engine requirement.
- `npm install` completes without dependency resolution errors.
- `npm audit --json` no longer reports the current Vite/esbuild moderate findings.
- `npm run typecheck` passes.
- `npm run lint` passes.
- `npm run build` passes.
- `npm run test` passes.
- API smoke tests pass for config status, integration test, IOC investigation, IOC report export, and architecture threat model.
- Browser smoke tests pass on desktop and mobile, with no console errors and no horizontal overflow.
- Graph rendering is non-empty, and graph/list toggles work for IOC and architecture threat modeling.

## 7. Rollback Strategy

If Vite 8 causes a blocking incompatibility that cannot be fixed safely:

- First try keeping Vite 8 while temporarily using the prior compatible React plugin version only if plugin-react 6 is the proven cause.
- If Vite 8 itself is the proven blocker, revert `vite`, `@vitejs/plugin-react`, `package-lock.json`, and any Vite-specific config edits together.
- Do not remove product features to make the migration pass.
- Record the blocker, reproduction steps, and failing command/browser scenario before rollback.

## 8. Verification Evidence

Implementation must leave command output and browser artifacts sufficient to prove the migration:

- Automated command results in the final implementation summary.
- API smoke-test response summaries.
- Browser screenshots saved under `artifacts/` for desktop and mobile validation.
