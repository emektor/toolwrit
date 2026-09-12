# Releasing Leash

Everything here has been rehearsed except the four steps that need an account
someone owns. Those are marked **[you]**; the rest is already done or is a
command you can paste.

## Layout

The project is two packages that share one hash chain, so they are released
together from one repository:

```
shortleash/                 <- repository root
├── .github/workflows/ci.yml
├── leash/                  <- TypeScript package, published to npm as `shortleash`
└── leash-py/               <- Python package, published to PyPI as `shortleash`
```

Both publish under the name `shortleash`; both install a CLI called `leash`.
The npm name `leash` is taken by an abandoned 2016 package, but a `bin` name is
not globally reserved, so the command is `leash` on both sides.

## Extracting from the parent repository

The code currently lives inside another repository. To lift it out with its
history:

```sh
# 1. [you] create an empty github.com/emektor/shortleash (no README, no licence)

# 2. build the standalone tree
git clone <parent-repo> /tmp/extract && cd /tmp/extract
git checkout claude/bi-model-capacity-middleware-7n9shg
git filter-repo --path leash/ --path leash-py/   # or: pip install git-filter-repo

# 3. the workflow moves to the root, where GitHub looks for it
mkdir -p .github/workflows && git mv leash/.github/workflows/ci.yml .github/workflows/ci.yml
git rm -r --cached leash/.github && rmdir -p leash/.github/workflows 2>/dev/null || true

# 4. push
git remote add origin git@github.com:emektor/shortleash.git
git push -u origin HEAD:main
```

If `git filter-repo` is unavailable, copying the two directories into a fresh
repository is acceptable — the commit history is nice to keep for due diligence
but is not load-bearing.

## Before publishing anything

```sh
cd leash     && npm ci && npm run typecheck && npm test && npm run build
cd ../leash-py && python -m pytest -q
```

Both suites must be green. CI runs these plus a cross-language job that proves
a chain written by one implementation verifies with the other and that the
entry hashes are equal — if that job ever fails, do not publish; the two
implementations have drifted and every claim about chain compatibility is void.

## npm

```sh
# [you] npm login   (an npm account with 2FA is fine; publishing will prompt)
cd leash
npm pack --dry-run          # read the file list once, on purpose
npm publish --access public # prepublishOnly runs the tests and build first
```

Verify the release the way a stranger would:

```sh
cd "$(mktemp -d)" && npm init -y && npm install shortleash
./node_modules/.bin/leash --version
```

## PyPI

```sh
# [you] a PyPI account and an API token (~/.pypirc, or TWINE_* env vars)
cd leash-py
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Verify:

```sh
python -m venv /tmp/v && /tmp/v/bin/pip install shortleash
/tmp/v/bin/leash --help
```

## Domain

**[you]** `shortleash.com` and `shortleash.dev` looked unregistered when checked
by DNS, which is an indication and not a guarantee — confirm at a registrar
before relying on either.

## Versioning

`0.1.0` on both. Keep the two versions identical: they share a wire format, and
a user pairing npm 0.2 with PyPI 0.1 must be able to tell at a glance that they
have mismatched halves.

Anything that changes what goes into an audit entry is a breaking change for
the chain even when the API is untouched, because logs written by the old
version will no longer match the new one's shape. Bump accordingly and say so
in the release notes.

## What is deliberately not automated

No release workflow publishes on a tag. For a project whose whole claim is that
it fails closed, a human pressing the button on each release is the right
amount of friction.
