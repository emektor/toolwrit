# Releasing Toolwrit

Everything here has been rehearsed except the four steps that need an account
someone owns. Those are marked **[you]**; the rest is already done or is a
command you can paste.

## Layout

The project is two packages that share one hash chain, so they are released
together from one repository:

```
toolwrit/                 <- repository root
├── .github/workflows/ci.yml
├── js/                     <- TypeScript package, published to npm as `toolwrit`
└── python/                 <- Python package, published to PyPI as `toolwrit`
```

Both publish under the name `toolwrit`; both install a CLI called `toolwrit`.
The package name and the command are the same word on both sides — there is no
need for the shorter-name-plus-different-binary split the project used before.

**[you]** confirm `toolwrit` is free on npm and on PyPI immediately before
publishing. It was chosen because it is not taken and does not collide with
anything in this category, but neither registry reserves a name until you push.

## Before publishing anything

```sh
cd js       && npm ci && npm run typecheck && npm test && npm run build
cd ../python  && python -m pytest -q
```

Both suites must be green. CI runs these plus a cross-language job that proves
a chain written by one implementation verifies with the other and that the
entry hashes are equal — if that job ever fails, do not publish; the two
implementations have drifted and every claim about chain compatibility is void.

## npm

```sh
# [you] npm login   (an npm account with 2FA is fine; publishing will prompt)
cd js
npm pack --dry-run          # read the file list once, on purpose
npm publish --access public # prepublishOnly runs the tests and build first
```

Verify the release the way a stranger would:

```sh
cd "$(mktemp -d)" && npm init -y && npm install toolwrit
./node_modules/.bin/toolwrit --version
```

## PyPI

```sh
# [you] a PyPI account and an API token (~/.pypirc, or TWINE_* env vars)
cd python
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

Verify:

```sh
python -m venv /tmp/v && /tmp/v/bin/pip install toolwrit
/tmp/v/bin/toolwrit --help
```

## The landing page

No domain. The launch links to this repository, which is where a reader wants to
end up anyway, and a hyphenated or half-remembered domain is worth less than
nothing. `site/index.html` is one self-contained file — serve it from GitHub
Pages by pointing Settings -> Pages at the branch, or drop it on any host later
if a domain is ever worth buying.

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
