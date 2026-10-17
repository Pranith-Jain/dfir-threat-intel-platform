/**
 * `api/` view of the shared caught-error stringifier.
 *
 * Most `api/src/lib/*.ts` modules are symlinks to `worker/lib/*`, so
 * `./err` would otherwise land on this path and resolve against `api/src/lib`
 * — where a relative re-export inside the worker copy points at the wrong
 * place. A real file (rather than a symlink) gives each tree a path that only
 * it takes, so both `import { errMessage } from './err'` spellings resolve to
 * the same single implementation in `src/lib/log.ts`.
 */
export { errMessage } from '../../../worker/lib/err';
