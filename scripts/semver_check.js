// npm's own semver, executed in the runner (protocol §5.4).
//
// R36 answered range questions from a frozen offline ledger because the derivation
// environment may not run Node. This pipeline may, and it has to judge versions the
// ledger never saw - anything published after snapshot_T. Same implementation, same
// semantics, different execution site. Nothing here reimplements range logic.
//
//   node semver_check.js satisfies <version> <range>
//   node semver_check.js max '["1.2.3","1.10.0"]'
//
// Always prints one JSON object. An undecidable input yields {"error": ...} and the
// caller records `semver_undecidable` rather than guessing.

const semver = require('semver');

function main() {
  const [op, ...args] = process.argv.slice(2);
  try {
    if (op === 'satisfies') {
      const [version, range] = args;
      if (!semver.valid(version)) {
        return { error: 'invalid_version', version };
      }
      if (!semver.validRange(range)) {
        return { error: 'invalid_range', range };
      }
      // includePrerelease matches how the offline oracle was asked, so a prerelease
      // install is not silently excluded from a range that brackets it.
      return { result: semver.satisfies(version, range, { includePrerelease: true }) };
    }
    if (op === 'max') {
      const versions = JSON.parse(args[0]).filter((v) => semver.valid(v));
      if (versions.length === 0) return { error: 'no_valid_versions' };
      return { result: semver.sort(versions).pop() };
    }
    return { error: 'unknown_op', op };
  } catch (err) {
    return { error: String(err && err.message ? err.message : err) };
  }
}

process.stdout.write(JSON.stringify(main()) + '\n');
